# Contributing to `@zkcoins/sdk`

Thanks for the interest. The SDK is a small library with strict guarantees, so the contribution rules lean conservative.

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

## Releasing

Releases are gated by `npm version` plus the auto-release-pr workflow. The version field in `package.json` is the single source of truth — `src/version.ts` is regenerated from it by `scripts/sync-version.cjs` (wired in as the `version` lifecycle hook in `package.json#scripts`). Hand-editing the version field anywhere is unnecessary and surfaced loudly by `test/version.test.ts` if attempted.

End-to-end flow for a release:

```bash
# On develop, with all feature work merged and committed.
npm version patch   # or minor / major
# ↑ This bumps package.json, runs sync-version.cjs (which updates
#   src/version.ts and stages it), creates a single "v0.1.2" commit
#   with both files, and creates a local tag v0.1.2.

git push origin develop
# ↑ Pushes the bump commit. The auto-release-pr workflow opens
#   (or updates) "Release: develop -> main" with the bump diff
#   included. Review and merge as a maintainer.

git push origin v0.1.2
# ↑ Pushes the tag. publish.yaml triggers, runs the full
#   pre-publish gate again, and `npm publish --provenance` ships
#   @zkcoins/sdk@0.1.2 to npm with OIDC provenance attestation.
```

The tag push is the "send it" step — gated by the maintainer's explicit action after the release PR has merged to `main`. Never push the tag before the merge: publish would ship from a develop-only commit before the main branch has caught up.

If the auto-release-pr workflow fails or you need to amend mid-release: don't force-push the tag (npm publish would reject the same version anyway). Bump again (`npm version patch` produces v0.1.3) and start over — versions are cheap, history is forever.

## Issues

For bugs: include the SDK version (`@zkcoins/sdk@X.Y.Z`), the runtime (Node version / browser / RN), a minimal reproduction, and the actual vs expected output. For features: link the consumer use case (a wallet integration, an example, an issue in `zk-coins/node` etc.) — the SDK does not add features speculatively.

## License

MIT — by submitting a PR you agree your contribution is licensed under the same terms.
