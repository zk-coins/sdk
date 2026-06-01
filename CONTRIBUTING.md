# Contributing to `@zkcoins/sdk`

Thanks for the interest. The SDK is a small library with strict guarantees, so the contribution rules lean conservative.

## Trust model — node is trusted, wallet is thin

zkCoins is built around a single trust assumption: **the wallet trusts the node it talks to.** The only line the node is not allowed to cross is the wallet's private key — that stays in the wallet. Everything else may be delegated.

This is a hard project rule. It shapes every design and implementation decision:

- **No anti-node logic in the wallet or SDK.** No client-side proof verification, no scan loops, no view-key / spend-key splits, no consistency checks against a second node, no "node integrity" indicators in the UI. If a feature exists to reduce trust in the node, it does not belong in the wallet or SDK.
- **Self-hosting is the escape hatch.** Users who do not want to trust the public operator run their own node. The wallet must always be able to switch to a different node by changing a single configuration value.
- **The node is built so that self-hosting is easy.** Single container, documented configuration, deterministic state, no operator-specific dependencies.
- **The SDK and wallet stay thin.** They expose seed + address + the small set of operations every familiar wallet SDK exposes. Integrators (Cake Wallet, LayerZ, BlueWallet, …) should be able to wire zkCoins up with the same effort as adding a second Bitcoin-family chain.

When in doubt about whether a feature belongs in the wallet, SDK, or node: if it exists to reduce trust in the node, build it node-side, or document self-hosting as the answer. This rule is mirrored verbatim in [`zk-coins/node`](https://github.com/zk-coins/node/blob/develop/CONTRIBUTING.md), [`zk-coins/sdk`](https://github.com/zk-coins/sdk/blob/develop/CONTRIBUTING.md), [`zk-coins/app`](https://github.com/zk-coins/app/blob/develop/CONTRIBUTING.md), and [`zk-coins/docs`](https://github.com/zk-coins/docs/blob/develop/CONTRIBUTING.md).

## Scope

`@zkcoins/sdk` is **pure TypeScript** — no WASM, no native modules, no environment-specific code paths. It must run identically in Node 22+, modern browsers, and React Native (Expo + bare workflow). Any change that breaks this is rejected on principle, even if it would simplify the SDK internally.

Cryptographic primitives come from audited upstream libraries:

- `@scure/bip39` — BIP-39 mnemonic.
- `@scure/bip32` — BIP-32 HD derivation.
- `@noble/curves/secp256k1` — secp256k1 + Schnorr (BIP-340).
- `@noble/hashes` — SHA-256.

Do not roll your own crypto. If a primitive is missing, add it via these libraries (or escalate the discussion in an issue).

## Branch flow

```
feature/* → staging → develop → main
```

- **Open feature PRs against `staging`** — `staging` is the integration buffer where multiple feature branches accumulate before being promoted in batches to `develop`.
- **`develop` is auto-PR'd from `staging`** by `auto-release-pr-staging.yaml`. The Promote PR runs the slim CI (lint, typecheck, build, test, cross-tests).
- **`main` is auto-PR'd from `develop`** by `auto-release-pr.yaml`. The Release PR is what the maintainer merges to cut a release.
- After `main` merges, tag the version (`git tag v0.1.0 && git push origin v0.1.0`) — that triggers `publish.yaml`, which runs the full gate one more time and publishes to npm with provenance.
- `develop` and `main` reject direct pushes. Hotfixes still go through `staging`.
- Never force-push, never amend a published commit, never squash on the agent side — the maintainer squashes at merge time if needed.

## Test gates

Every PR must pass:

1. **Lint + typecheck + build** — `npm run lint && npm run typecheck && npm run build`. `dist/` must be produced (ESM + CJS + `.d.ts`).
2. **Unit tests with 100 % coverage gate** — `npm run test:coverage`. Vitest enforces `lines: 100, functions: 100, statements: 100, branches: 95` on `src/*` (excluding `src/index.ts` and `src/types.ts` which are pure re-exports). A line that genuinely cannot be hit either gets a test or a file-level exclusion with a one-line comment.
3. **Cross-tests** — `npm run test:cross`. Spawns the Rust shim in `test/cross-rust/shim/` and compares JS vs Rust output for 100 randomized inputs per cryptographic primitive. **A green cross-test is the single load-bearing guarantee** that the pure-JS reimpl matches the protocol spec encoded in `zk-coins/app/rust/client/`.

CI runs all three on every PR. Drafts skip CI by convention (re-enable by marking ready-for-review).

## Cross-test infrastructure

The shim at `test/cross-rust/shim/` is a JSON-stdin → JSON-stdout CLI mirroring every cryptographic function from the SDK. The Rust dependencies (`bitcoin`, `secp256k1`, `sha2`, `hex`, `serde_json`) match those used by `zk-coins/app/rust/client/`, so the shim's behaviour is byte-equivalent to the app's WASM source.

When you add a new primitive to `src/derivation.ts` or `src/signing.ts`:

1. Add the matching dispatch arm in `test/cross-rust/shim/src/main.rs`.
2. Add a generator + assertion block in `test/cross-rust/cross.test.ts`.
3. Run `npm run test:cross` locally before pushing — CI will re-run, but feedback loop is faster locally.

If a future primitive cannot be reasonably cross-tested (e.g. it's a JS-only convenience over already-tested primitives), document the omission in `test/cross-rust/README.md`.

## Code style

- Prettier 3 with `singleQuote: true, trailingComma: 'all', printWidth: 100`. Run `npm run lint:fix` to apply.
- ESLint with `@typescript-eslint/recommended-requiring-type-checking`. Floating promises are errors.
- `verbatimModuleSyntax: true` — type-only imports must use `import type`.
- No `any`. No `// @ts-ignore`. If you need to escape the type system, write a justifying comment and use `as unknown as T`.
- No inline `console.log` in committed code. Errors via `console.error` are fine; everything else is for tests.

## Commit messages

Follow [Conventional Commits](https://conventionalcommits.org/):

```
type(scope): summary

Longer body explaining WHY, not WHAT — the diff already shows what.
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`, `build`, `perf`.

## Issues

For bugs: include the SDK version (`@zkcoins/sdk@X.Y.Z`), the runtime (Node version / browser / RN), a minimal reproduction, and the actual vs expected output. For features: link the consumer use case (a wallet integration, an example, an issue in `zk-coins/node` etc.) — the SDK does not add features speculatively.

## License

MIT — by submitting a PR you agree your contribution is licensed under the same terms.
