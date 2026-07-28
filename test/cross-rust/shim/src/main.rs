//! zkcoins-sdk-shim — JSON-stdin → JSON-stdout CLI for JS↔Rust crypto parity.
//!
//! Independent Rust reimplementation of the pure-JS surface in
//! `src/derivation.ts` and `src/signing.ts`. Uses the same crates
//! (`bitcoin` 0.32, `bip39`, `sha2`) as `zk-coins/app/rust/client` so the
//! BIP-32 / BIP-340 path is real crypto, not a mock.
//!
//! Wire protocol: one JSON object per stdin line (or a single object on
//! stdin). Request shape:
//!
//! ```json
//! { "op": "<name>", ...op-specific fields }
//! ```
//!
//! Response on success:
//!
//! ```json
//! { "ok": true, "result": <value> }
//! ```
//!
//! Response on error:
//!
//! ```json
//! { "ok": false, "error": "<message>" }
//! ```
//!
//! See `test/cross-rust/README.md` for the parity scope decision (DoD §6(b)).

use std::io::{self, BufRead, Write};
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"ok": false, "error": format!("stdin read: {e}")})
                );
                let _ = stdout.flush();
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match handle_line(trimmed) {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => json!({"ok": false, "error": e}),
        };
        if writeln!(stdout, "{response}").is_err() {
            break;
        }
        let _ = stdout.flush();
    }
}

fn handle_line(line: &str) -> Result<Value, String> {
    let req: Value =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON request: {e}"))?;
    let op = req
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing string field `op`".to_string())?;
    match op {
        "validate_mnemonic" => {
            let phrase = require_str(&req, "phrase")?;
            Ok(Value::Bool(validate_mnemonic(phrase)))
        }
        "mnemonic_from_entropy" => {
            let entropy_hex = require_str(&req, "entropy_hex")?;
            Ok(Value::String(mnemonic_from_entropy(entropy_hex)?))
        }
        "account_from_seed" => {
            let seed_hex = require_str(&req, "seed_hex")?;
            Ok(serde_json::to_value(account_from_seed(seed_hex)?).map_err(|e| e.to_string())?)
        }
        "account_from_mnemonic" => {
            let mnemonic = require_str(&req, "mnemonic")?;
            // Callers must always supply `passphrase` (use "" for none).
            // Silent omission would mask a missing field as empty BIP-39 salt.
            let passphrase = require_str(&req, "passphrase")?;
            Ok(serde_json::to_value(account_from_mnemonic(mnemonic, passphrase)?)
                .map_err(|e| e.to_string())?)
        }
        "derive_public_keys" => {
            let xpriv = require_str(&req, "xpriv")?;
            let num_pubkeys = require_u32(&req, "num_pubkeys")?;
            Ok(serde_json::to_value(derive_public_keys(xpriv, num_pubkeys)?)
                .map_err(|e| e.to_string())?)
        }
        "derive_signing_key" => {
            let xpriv = require_str(&req, "xpriv")?;
            let index = require_u32(&req, "index")?;
            Ok(Value::String(derive_signing_key(xpriv, index)?))
        }
        "sign_schnorr" => {
            let private_key_hex = require_str(&req, "private_key_hex")?;
            let hash_hex = require_str(&req, "hash_hex")?;
            Ok(Value::String(sign_schnorr(private_key_hex, hash_hex)?))
        }
        "create_commitment" => {
            let xpriv = require_str(&req, "xpriv")?;
            let num_pubkeys = require_u32(&req, "num_pubkeys")?;
            let account_state_hash_hex = require_str(&req, "account_state_hash_hex")?;
            let output_coins_root_hex = require_str(&req, "output_coins_root_hex")?;
            Ok(serde_json::to_value(create_commitment(
                xpriv,
                num_pubkeys,
                account_state_hash_hex,
                output_coins_root_hex,
            )?)
            .map_err(|e| e.to_string())?)
        }
        other => Err(format!("unknown op: {other}")),
    }
}

fn require_str<'a>(req: &'a Value, field: &str) -> Result<&'a str, String> {
    req.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing string field `{field}`"))
}

fn require_u32(req: &Value, field: &str) -> Result<u32, String> {
    req.get(field)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("missing u32 field `{field}`"))
}

fn validate_mnemonic(phrase: &str) -> bool {
    phrase.parse::<bip39::Mnemonic>().is_ok()
}

fn mnemonic_from_entropy(entropy_hex: &str) -> Result<String, String> {
    let entropy = hex::decode(entropy_hex).map_err(|e| format!("invalid entropy hex: {e}"))?;
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("invalid entropy for BIP-39: {e}"))?;
    Ok(mnemonic.to_string())
}

#[derive(Serialize)]
struct AccountKeys {
    address: String,
    xpriv: String,
    #[serde(rename = "numPubkeys")]
    num_pubkeys: u32,
}

fn account_from_seed(seed_hex: &str) -> Result<AccountKeys, String> {
    let seed = hex::decode(seed_hex).map_err(|e| format!("invalid seed hex: {e}"))?;
    let master = Xpriv::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Xpriv::new_master failed: {e}"))?;
    account_from_master(master)
}

fn account_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<AccountKeys, String> {
    let mnemonic: bip39::Mnemonic = mnemonic
        .parse()
        .map_err(|e: bip39::Error| format!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed(passphrase);
    let master = Xpriv::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Xpriv::new_master failed: {e}"))?;
    account_from_master(master)
}

fn account_from_master(master: Xpriv) -> Result<AccountKeys, String> {
    let secp = Secp256k1::new();
    let child0 = master
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .map_err(|e| format!("derive child 0: {e}"))?;
    let pk0 = child0.private_key.public_key(&secp);
    // Match the pure-JS SDK: address = SHA-256(compressed SEC1 pubkey at index 0).
    // (Spec V.2-ext / Poseidon owner is a separate, future parity surface — see README.)
    let address = sha256::Hash::hash(&pk0.serialize());
    Ok(AccountKeys {
        address: hex::encode(address.to_byte_array()),
        xpriv: master.to_string(),
        num_pubkeys: 0,
    })
}

#[derive(Serialize)]
struct PublicKeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "nextPublicKey")]
    next_public_key: String,
}

fn derive_public_keys(xpriv_str: &str, num_pubkeys: u32) -> Result<PublicKeyPair, String> {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::from_str(xpriv_str).map_err(|e| format!("invalid xpriv: {e}"))?;
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let current = xpub
        .derive_pub(&secp, &[ChildNumber::Normal { index: num_pubkeys }])
        .map_err(|e| format!("derive public {num_pubkeys}: {e}"))?;
    let next_index = num_pubkeys
        .checked_add(1)
        .ok_or_else(|| "num_pubkeys + 1 overflow".to_string())?;
    let next = xpub
        .derive_pub(&secp, &[ChildNumber::Normal { index: next_index }])
        .map_err(|e| format!("derive public {next_index}: {e}"))?;
    Ok(PublicKeyPair {
        public_key: hex::encode(current.public_key.serialize()),
        next_public_key: hex::encode(next.public_key.serialize()),
    })
}

fn derive_signing_key(xpriv_str: &str, index: u32) -> Result<String, String> {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::from_str(xpriv_str).map_err(|e| format!("invalid xpriv: {e}"))?;
    let child = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index }])
        .map_err(|e| format!("derive signing key {index}: {e}"))?;
    Ok(hex::encode(child.private_key.secret_bytes()))
}

fn sign_schnorr(private_key_hex: &str, hash_hex: &str) -> Result<String, String> {
    let priv_bytes = hex::decode(private_key_hex).map_err(|e| format!("invalid private key hex: {e}"))?;
    if priv_bytes.len() != 32 {
        return Err(format!(
            "private key must be 32 bytes, got {}",
            priv_bytes.len()
        ));
    }
    let secret_key =
        SecretKey::from_slice(&priv_bytes).map_err(|e| format!("invalid secret key: {e}"))?;
    let hash_bytes = hex::decode(hash_hex).map_err(|e| format!("invalid hash hex: {e}"))?;
    if hash_bytes.len() != 32 {
        return Err(format!("hash must be 32 bytes, got {}", hash_bytes.len()));
    }
    let msg =
        Message::from_digest_slice(&hash_bytes).map_err(|e| format!("invalid message: {e}"))?;
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    // Deterministic BIP-340: no auxiliary randomness — matches JS
    // `schnorr.sign(hash, privateKey, new Uint8Array(32))` and Rust
    // `sign_schnorr_no_aux_rand`.
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    Ok(hex::encode(sig.as_ref()))
}

#[derive(Serialize, Deserialize)]
struct Commitment {
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
    message: String,
}

fn create_commitment(
    xpriv_str: &str,
    num_pubkeys: u32,
    account_state_hash_hex: &str,
    output_coins_root_hex: &str,
) -> Result<Commitment, String> {
    let ash = hex::decode(account_state_hash_hex)
        .map_err(|e| format!("invalid account_state_hash hex: {e}"))?;
    let ocr = hex::decode(output_coins_root_hex)
        .map_err(|e| format!("invalid output_coins_root hex: {e}"))?;
    let mut message = Vec::with_capacity(ash.len() + ocr.len());
    message.extend_from_slice(&ash);
    message.extend_from_slice(&ocr);

    let digest: [u8; 32] = Sha256::digest(&message).into();
    let private_key_hex = derive_signing_key(xpriv_str, num_pubkeys)?;
    let signature = sign_schnorr(&private_key_hex, &hex::encode(digest))?;
    let pubs = derive_public_keys(xpriv_str, num_pubkeys)?;

    Ok(Commitment {
        public_key: pubs.public_key,
        signature,
        message: hex::encode(message),
    })
}
