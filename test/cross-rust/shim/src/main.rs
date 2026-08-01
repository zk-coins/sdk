//! zkcoins-sdk-shim — JSON-stdin → JSON-stdout CLI for JS↔Rust crypto parity.
//!
//! Independent Rust reimplementation of the pure-JS surface in
//! `src/derivation.ts`, `src/signing.ts`, and `src/v1/` (§3.2 S2C + §1.7.10
//! half-agg). Uses the same crates (`bitcoin` 0.32, `bip39`, `sha2`) so the
//! BIP-32 / BIP-340 / SHA-256 path is real crypto, not a mock.
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
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::{Keypair, Message, Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
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
        // ── v1 §3.2 / §1.7.10 parity ops ─────────────────────────────────
        "transition_sign" => {
            // Fixture-nonce path only (deterministic). Production CSPRNG
            // nonces are not parity-comparable.
            let secret_key_hex = require_str(&req, "secret_key_hex")?;
            let m_sc_hex = require_str(&req, "m_sc_hex")?;
            let network = require_str(&req, "network")?;
            Ok(serde_json::to_value(transition_sign_fixture(
                secret_key_hex,
                m_sc_hex,
                network,
            )?)
            .map_err(|e| e.to_string())?)
        }
        "transition_verify" => {
            let public_key_hex = require_str(&req, "public_key_hex")?;
            let signature_hex = require_str(&req, "signature_hex")?;
            let network = require_str(&req, "network")?;
            Ok(Value::Bool(transition_verify(
                public_key_hex,
                signature_hex,
                network,
            )?))
        }
        "comm_verify" => {
            let r_hex = require_str(&req, "r_hex")?;
            let m_sc_hex = require_str(&req, "m_sc_hex")?;
            let r_prime_hex = require_str(&req, "r_prime_hex")?;
            Ok(Value::Bool(comm_verify_op(r_hex, m_sc_hex, r_prime_hex)?))
        }
        "half_agg" => {
            let members = require_members(&req)?;
            Ok(serde_json::to_value(half_agg_op(&members)?).map_err(|e| e.to_string())?)
        }
        "aggregate_verify" => {
            let members = require_members_pk_r(&req)?;
            let s_agg_hex = require_str(&req, "s_agg_hex")?;
            let network = require_str(&req, "network")?;
            Ok(Value::Bool(aggregate_verify_op(&members, s_agg_hex, network)?))
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

// ═══════════════════════════════════════════════════════════════════════════
// v1 §3.2 transition signing + §1.7.10 half-aggregation (parity surface)
// ═══════════════════════════════════════════════════════════════════════════

fn m_state_bytes(network: &str) -> Result<&'static [u8], String> {
    match network {
        "mainnet" => Ok(b"zkCoins/v1/StateUpdate/mainnet"),
        "testnet" => Ok(b"zkCoins/v1/StateUpdate/testnet"),
        "regtest" => Ok(b"zkCoins/v1/StateUpdate/regtest"),
        other => Err(format!(
            "unknown network {other:?}; expected mainnet|testnet|regtest"
        )),
    }
}

fn parse_hex32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid {label} hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{label} must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex64(hex_str: &str, label: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid {label} hex: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("{label} must be 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(message);
    Sha256::digest(&preimage).into()
}

/// int(bytes) mod n as a 32-byte big-endian scalar in [0, n).
fn scalar_mod_n(bytes: &[u8; 32]) -> [u8; 32] {
    if bytes.as_slice() < CURVE_ORDER.as_slice() {
        return *bytes;
    }
    // bytes ≥ n: subtract n once (a 256-bit hash is < 2n).
    let mut out = *bytes;
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let b = out[i] as u16;
        let s = CURVE_ORDER[i] as u16 + borrow;
        if b >= s {
            out[i] = (b - s) as u8;
            borrow = 0;
        } else {
            out[i] = (b + 256 - s) as u8;
            borrow = 1;
        }
    }
    out
}

fn is_canonical_scalar(bytes: &[u8; 32]) -> bool {
    bytes.as_slice() < CURVE_ORDER.as_slice()
}

fn secret_from_be(bytes: &[u8; 32]) -> Result<SecretKey, String> {
    SecretKey::from_slice(bytes).map_err(|e| format!("invalid secret scalar: {e}"))
}

fn scalar_from_be(bytes: &[u8; 32]) -> Result<Scalar, String> {
    Scalar::from_be_bytes(*bytes).map_err(|_| "scalar out of range (≥ n)".to_string())
}

fn xonly_even_pk(bytes: &[u8; 32]) -> Result<(XOnlyPublicKey, PublicKey), String> {
    let xonly =
        XOnlyPublicKey::from_slice(bytes).map_err(|e| format!("invalid x-only point: {e}"))?;
    let pk = PublicKey::from_x_only_public_key(xonly, Parity::Even);
    Ok((xonly, pk))
}

/// BIP-340 key normalisation → (d_bytes, pk_xonly_bytes).
fn bip340_normalise(secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
    let secp = Secp256k1::new();
    let sk = secret_from_be(secret)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, parity) = keypair.x_only_public_key();
    let d = if parity == Parity::Odd {
        sk.negate()
    } else {
        sk
    };
    Ok((d.secret_bytes(), xonly.serialize()))
}

#[derive(Serialize)]
struct TransitionSignResult {
    r_prime: String,
    t: String,
    r: String,
    e: String,
    s: String,
    signature: String,
    s2c_nonce: String,
    pk: String,
    nonce_counter: u32,
}

/// V.8 fixture nonce rule (test-vector only). Mirrors the JS
/// `signTransitionWithFixtureNonce`.
fn transition_sign_fixture(
    secret_key_hex: &str,
    m_sc_hex: &str,
    network: &str,
) -> Result<TransitionSignResult, String> {
    let secret = parse_hex32(secret_key_hex, "secret_key")?;
    let m_sc = parse_hex32(m_sc_hex, "m_sc")?;
    let m_state = m_state_bytes(network)?;
    let (d_bytes, pk_bytes) = bip340_normalise(&secret)?;
    let secp = Secp256k1::new();

    let aux = tagged_hash(b"BIP0340/aux", &[0u8; 32]);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = d_bytes[i] ^ aux[i];
    }

    for ctr in 0u32..10_000 {
        let mut nonce_preimage = Vec::with_capacity(32 + 32 + m_state.len() + 4);
        nonce_preimage.extend_from_slice(&masked);
        nonce_preimage.extend_from_slice(&pk_bytes);
        nonce_preimage.extend_from_slice(m_state);
        nonce_preimage.extend_from_slice(&ctr.to_be_bytes());
        let rand_ctr = tagged_hash(b"BIP0340/nonce", &nonce_preimage);
        let k_bytes = scalar_mod_n(&rand_ctr);
        if k_bytes == [0u8; 32] {
            continue;
        }
        let mut k_sk = match secret_from_be(&k_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut r_prime_pk = PublicKey::from_secret_key(&secp, &k_sk);
        let r_prime_parity = r_prime_pk.x_only_public_key().1;
        // §3.2 step 1b
        if r_prime_parity == Parity::Odd {
            k_sk = k_sk.negate();
            r_prime_pk = PublicKey::from_secret_key(&secp, &k_sk);
        }
        let r_prime_bytes = r_prime_pk.x_only_public_key().0.serialize();

        let mut tweak_preimage = [0u8; 64];
        tweak_preimage[..32].copy_from_slice(&r_prime_bytes);
        tweak_preimage[32..].copy_from_slice(&m_sc);
        let t_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
        // Unreduced: int(t) ≥ n → redraw.
        if !is_canonical_scalar(&t_bytes) {
            continue;
        }
        let t_scalar = scalar_from_be(&t_bytes)?;
        let r_pk = match r_prime_pk.add_exp_tweak(&secp, &t_scalar) {
            Ok(p) => p,
            Err(_) => continue, // infinity
        };
        let (r_xonly, r_parity) = r_pk.x_only_public_key();
        if r_parity == Parity::Odd {
            continue; // step 3b: y(R) odd → redraw
        }
        let r_bytes = r_xonly.serialize();

        let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
        challenge_preimage.extend_from_slice(&r_bytes);
        challenge_preimage.extend_from_slice(&pk_bytes);
        challenge_preimage.extend_from_slice(m_state);
        let e_bytes = scalar_mod_n(&tagged_hash(b"BIP0340/challenge", &challenge_preimage));
        let d_sk = secret_from_be(&d_bytes)?;
        // s = k' + t + e·d  (e = 0 is allowed; mul_tweak(0) is invalid, so branch)
        let k_plus_t = k_sk
            .add_tweak(&t_scalar)
            .map_err(|e| format!("k'+t failed: {e}"))?;
        let s_sk = if e_bytes == [0u8; 32] {
            k_plus_t
        } else {
            let e_scalar = scalar_from_be(&e_bytes)?;
            let e_d = d_sk
                .mul_tweak(&e_scalar)
                .map_err(|e| format!("e·d failed: {e}"))?;
            let e_d_scalar = Scalar::from_be_bytes(e_d.secret_bytes())
                .map_err(|_| "e·d out of range".to_string())?;
            k_plus_t
                .add_tweak(&e_d_scalar)
                .map_err(|e| format!("s assemble failed: {e}"))?
        };
        let s_bytes = s_sk.secret_bytes();
        if s_bytes == [0u8; 32] {
            continue;
        }

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&s_bytes);

        return Ok(TransitionSignResult {
            r_prime: hex::encode(r_prime_bytes),
            t: hex::encode(t_bytes),
            r: hex::encode(r_bytes),
            e: hex::encode(e_bytes),
            s: hex::encode(s_bytes),
            signature: hex::encode(signature),
            s2c_nonce: hex::encode(r_prime_bytes),
            pk: hex::encode(pk_bytes),
            nonce_counter: ctr,
        });
    }
    Err("transition_sign: exhausted redraw budget".to_string())
}

fn transition_verify(
    public_key_hex: &str,
    signature_hex: &str,
    network: &str,
) -> Result<bool, String> {
    let pk_bytes = parse_hex32(public_key_hex, "public_key")?;
    let sig = parse_hex64(signature_hex, "signature")?;
    let m_state = m_state_bytes(network)?;
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..]);
    if !is_canonical_scalar(&s_bytes) || s_bytes == [0u8; 32] {
        return Ok(false);
    }
    let secp = Secp256k1::new();
    let (_, r_pk) = match xonly_even_pk(&r_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let (_, p_pk) = match xonly_even_pk(&pk_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
    challenge_preimage.extend_from_slice(&r_bytes);
    challenge_preimage.extend_from_slice(&pk_bytes);
    challenge_preimage.extend_from_slice(m_state);
    let e_bytes = scalar_mod_n(&tagged_hash(b"BIP0340/challenge", &challenge_preimage));
    // rhs = R + e·P  (e = 0 → rhs = R)
    let rhs = if e_bytes == [0u8; 32] {
        r_pk
    } else {
        let e_scalar = match scalar_from_be(&e_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let e_p = match p_pk.mul_tweak(&secp, &e_scalar) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        match r_pk.combine(&e_p) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        }
    };
    // lhs = s·G
    let s_sk = match secret_from_be(&s_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let lhs = PublicKey::from_secret_key(&secp, &s_sk);
    Ok(lhs == rhs)
}

fn comm_verify_op(r_hex: &str, m_sc_hex: &str, r_prime_hex: &str) -> Result<bool, String> {
    let r_bytes = parse_hex32(r_hex, "r")?;
    let m_sc = parse_hex32(m_sc_hex, "m_sc")?;
    let r_prime = parse_hex32(r_prime_hex, "r_prime")?;
    let secp = Secp256k1::new();
    let (_, commitment) = match xonly_even_pk(&r_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let (_, opening) = match xonly_even_pk(&r_prime) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let mut tweak_preimage = [0u8; 64];
    tweak_preimage[..32].copy_from_slice(&r_prime);
    tweak_preimage[32..].copy_from_slice(&m_sc);
    let t_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
    // Unreduced: int(t) ≥ n → false.
    if !is_canonical_scalar(&t_bytes) {
        return Ok(false);
    }
    let t_scalar = match scalar_from_be(&t_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let opened = match opening.add_exp_tweak(&secp, &t_scalar) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let (_, opened_parity) = opened.x_only_public_key();
    if opened_parity == Parity::Odd {
        return Ok(false);
    }
    Ok(commitment == opened)
}

#[derive(Clone)]
struct MemberFull {
    pk: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

#[derive(Clone)]
struct MemberPkR {
    pk: [u8; 32],
    r: [u8; 32],
}

fn require_members(req: &Value) -> Result<Vec<MemberFull>, String> {
    let arr = req
        .get("members")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing array field `members`".to_string())?;
    if arr.is_empty() {
        return Err("members must be non-empty".to_string());
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, m) in arr.iter().enumerate() {
        let pk = require_str(m, "pk_hex").map_err(|e| format!("members[{i}]: {e}"))?;
        let r = require_str(m, "r_hex").map_err(|e| format!("members[{i}]: {e}"))?;
        let s = require_str(m, "s_hex").map_err(|e| format!("members[{i}]: {e}"))?;
        out.push(MemberFull {
            pk: parse_hex32(pk, &format!("members[{i}].pk"))?,
            r: parse_hex32(r, &format!("members[{i}].r"))?,
            s: parse_hex32(s, &format!("members[{i}].s"))?,
        });
    }
    Ok(out)
}

fn require_members_pk_r(req: &Value) -> Result<Vec<MemberPkR>, String> {
    let arr = req
        .get("members")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing array field `members`".to_string())?;
    if arr.is_empty() {
        return Err("members must be non-empty".to_string());
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, m) in arr.iter().enumerate() {
        let pk = require_str(m, "pk_hex").map_err(|e| format!("members[{i}]: {e}"))?;
        let r = require_str(m, "r_hex").map_err(|e| format!("members[{i}]: {e}"))?;
        out.push(MemberPkR {
            pk: parse_hex32(pk, &format!("members[{i}].pk"))?,
            r: parse_hex32(r, &format!("members[{i}].r"))?,
        });
    }
    Ok(out)
}

#[derive(Serialize)]
struct HalfAggResult {
    z: String,
    coefficients: Vec<String>,
    s_agg: String,
}

fn aggregation_coefficients(members: &[( [u8; 32], [u8; 32] )]) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    let domain = b"zkCoins/v1/HalfAgg";
    let mut transcript = Vec::with_capacity(domain.len() + 64 * members.len());
    transcript.extend_from_slice(domain);
    for (pk, r) in members {
        transcript.extend_from_slice(r);
        transcript.extend_from_slice(pk);
    }
    let z: [u8; 32] = Sha256::digest(&transcript).into();
    let mut coefficients = Vec::with_capacity(members.len());
    for j in 1..=members.len() {
        let mut preimage = [0u8; 36];
        preimage[..32].copy_from_slice(&z);
        preimage[32..].copy_from_slice(&(j as u32).to_be_bytes());
        let digest: [u8; 32] = Sha256::digest(preimage).into();
        coefficients.push(scalar_mod_n(&digest));
    }
    Ok((z, coefficients))
}

fn half_agg_op(members: &[MemberFull]) -> Result<HalfAggResult, String> {
    let pairs: Vec<([u8; 32], [u8; 32])> = members.iter().map(|m| (m.pk, m.r)).collect();
    // Canonical point check
    for (i, m) in members.iter().enumerate() {
        xonly_even_pk(&m.pk).map_err(|e| format!("member[{i}].pk: {e}"))?;
        xonly_even_pk(&m.r).map_err(|e| format!("member[{i}].r: {e}"))?;
        if !is_canonical_scalar(&m.s) {
            return Err(format!("member[{i}].s is not a canonical scalar"));
        }
    }
    let (z, coefficients) = aggregation_coefficients(&pairs)?;
    // s_agg = Σ aⱼ·sⱼ  via successive SecretKey tweaks on a running sum.
    // Start at 0 — SecretKey cannot be zero, so accumulate via mul+add.
    let mut s_agg_bytes = [0u8; 32];
    for (i, m) in members.iter().enumerate() {
        let a = &coefficients[i];
        if *a == [0u8; 32] || m.s == [0u8; 32] {
            continue;
        }
        let a_scalar = scalar_from_be(a)?;
        let s_sk = secret_from_be(&m.s)?;
        let term = s_sk
            .mul_tweak(&a_scalar)
            .map_err(|e| format!("a·s at {i}: {e}"))?;
        if s_agg_bytes == [0u8; 32] {
            s_agg_bytes = term.secret_bytes();
        } else {
            let acc = secret_from_be(&s_agg_bytes)?;
            let term_scalar = Scalar::from_be_bytes(term.secret_bytes())
                .map_err(|_| format!("term scalar at {i}"))?;
            s_agg_bytes = acc
                .add_tweak(&term_scalar)
                .map_err(|e| format!("s_agg add at {i}: {e}"))?
                .secret_bytes();
        }
    }
    Ok(HalfAggResult {
        z: hex::encode(z),
        coefficients: coefficients.iter().map(hex::encode).collect(),
        s_agg: hex::encode(s_agg_bytes),
    })
}

fn aggregate_verify_op(
    members: &[MemberPkR],
    s_agg_hex: &str,
    network: &str,
) -> Result<bool, String> {
    let s_agg = parse_hex32(s_agg_hex, "s_agg")?;
    if !is_canonical_scalar(&s_agg) {
        return Ok(false);
    }
    let m_state = m_state_bytes(network)?;
    let secp = Secp256k1::new();
    let pairs: Vec<([u8; 32], [u8; 32])> = members.iter().map(|m| (m.pk, m.r)).collect();
    let (_z, coefficients) = match aggregation_coefficients(&pairs) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };

    let mut rhs: Option<PublicKey> = None;
    for (i, m) in members.iter().enumerate() {
        let (_, r_pk) = match xonly_even_pk(&m.r) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let (_, p_pk) = match xonly_even_pk(&m.pk) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
        challenge_preimage.extend_from_slice(&m.r);
        challenge_preimage.extend_from_slice(&m.pk);
        challenge_preimage.extend_from_slice(m_state);
        let e_bytes = scalar_mod_n(&tagged_hash(b"BIP0340/challenge", &challenge_preimage));
        let e_scalar = match scalar_from_be(&e_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let e_p = match p_pk.mul_tweak(&secp, &e_scalar) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let sig_rhs = match r_pk.combine(&e_p) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        let a = &coefficients[i];
        let term = if *a == [0u8; 32] {
            // a = 0 → term is infinity; skip contribution
            continue;
        } else {
            let a_scalar = match scalar_from_be(a) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            match sig_rhs.mul_tweak(&secp, &a_scalar) {
                Ok(p) => p,
                Err(_) => return Ok(false),
            }
        };
        rhs = Some(match rhs {
            None => term,
            Some(acc) => match acc.combine(&term) {
                Ok(p) => p,
                Err(_) => return Ok(false),
            },
        });
    }
    let rhs = match rhs {
        Some(p) => p,
        None => {
            // All coefficients zero — only accepts s_agg = 0 (impossible as SecretKey).
            return Ok(s_agg == [0u8; 32]);
        }
    };
    if s_agg == [0u8; 32] {
        return Ok(false);
    }
    let s_sk = match secret_from_be(&s_agg) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let lhs = PublicKey::from_secret_key(&secp, &s_sk);
    Ok(lhs == rhs)
}
