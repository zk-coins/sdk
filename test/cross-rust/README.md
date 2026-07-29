# Cross-tests: JS SDK ↔ Rust reference (DoD §6(b))

This directory is the **Node↔SDK primitive parity suite** required by the
implementation plan DoD §6(b) and the [Implementation Mandate] step 4 /
spec V.7 parity matrix: the pure-JS SDK must reproduce the wallet-side
cryptographic surface bit-for-bit against an independent Rust
implementation.

## What runs

| Piece                | Role                                                                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shim/`              | Standalone JSON-stdin CLI (`zkcoins-sdk-shim`) using real `bitcoin` / `bip39` / `sha2` crates (same versions as `zk-coins/app/rust`). **Not a mock.** |
| `cross.test.ts`      | Spawns the release binary and compares JS vs Rust for each op on 100 randomized inputs (plus fixed vectors).                                          |
| `npm run test:cross` | Vitest config `vitest.cross.config.ts`. CI job `cross-tests` builds the shim then runs this.                                                          |

## Scope decision (documented — Spec leaves the live surface open)

DoD §6(b) and the V.7 matrix require byte-equal reproduction for every
row in the matrix that the **SDK actually implements**. Today the
published SDK surface is the legacy wallet primitives in
`src/derivation.ts` and `src/signing.ts`:

| Op                                              | Spec / V.7 link           | Criterion                     |
| ----------------------------------------------- | ------------------------- | ----------------------------- |
| BIP-39 validate / entropy→mnemonic              | V.2 foundation            | byte-equal phrase             |
| BIP-39 mnemonic → BIP-32 master xpriv + address | V.2 / historical wallet   | byte-equal `address`, `xpriv` |
| Non-hardened child pubkeys / signing key        | wallet surface            | byte-equal SEC1 / sk          |
| BIP-340 Schnorr (`no_aux_rand`)                 | V.5/V.8 signing layer     | byte-equal sig                |
| `createCommitment` (ash‖ocr → SHA-256 → sign)   | historical two-phase send | byte-equal commitment         |

**Not parity-checked — raw 32-byte `account_from_seed`.** The SDK keeps
`accountFromSeed` private; the public surface only exposes CSPRNG
`generateAccountKeys()` and mnemonic `generateAccountKeysFromMnemonic()`.
A parity case that rebuilt the seed path inside the test would compare
Rust against a test-local reimplementation, not the SDK — so that op is
omitted rather than claimed. Mnemonic → account still covers the shared
`accountFromSeed` helper with BIP-39's 64-byte seed.

**Explicitly not in this gate yet** (SDK has no implementation):

- Spec V.2-ext all-hardened + HKDF key hierarchy
- V.4 Poseidon digests (`E'₂₅₆`, `nk_commit`, `asset_id`, …)
- V.8 half-aggregation / sign-to-contract full fixture
- V.10 note encryption, V.11 nflog, V.12 NIP-17 wire

Those rows land as additional ops in this suite when the corresponding
SDK modules land. Expanding the gate without a JS implementation would
only re-test Rust against itself.

Address hashing in the live surface is **SHA-256(compressed pk₀)** —
matching the pure-JS SDK and the historical WASM client contract the
SDK was written against. Spec-conformant Poseidon owner
(`Hc` / `digest_to_bytes`) is part of the V.2-ext/V.4 follow-up, not
silently substituted here.

## Reproducible random samples

Randomized cases draw inputs from a tiny in-suite xorshift32 PRNG, not
from `crypto.randomBytes`. Default seed is `0x5eedc0de`; every run
prints the seed it used. Override with:

```bash
CROSS_RUST_SEED=0xdeadbeef npm run test:cross
```

On mismatch the assertion message includes the seed and the concrete
input (entropy, hash, ash/ocr, …) so the failing sample can be copied
into a fixed vector without re-running the full stream.

## Failure model

- Missing shim binary → the test suite **fails** (does not skip).
- Missing `test/cross-rust/shim/Cargo.toml` → CI **fails** (no
  `if exists == 'true'` skip).
- Any JS/Rust mismatch on a compared field → CI **fails**.

A gate that cannot go red is not a gate. The deliberate break exercise
is documented in the PR report for G17 (temporary mutation of a JS
primitive, red run, revert).

## Local use

```bash
# One-time / after shim changes:
cargo build --release --manifest-path test/cross-rust/shim/Cargo.toml

# Run parity suite:
npm run test:cross

# Same inputs as a prior run:
CROSS_RUST_SEED=0x5eedc0de npm run test:cross
```

The shim binary path expected by the tests is:

`test/cross-rust/shim/target/release/zkcoins-sdk-shim`
