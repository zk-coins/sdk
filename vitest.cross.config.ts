import { defineConfig } from 'vitest/config';

// Cross-tests live in test/cross-rust/ and spawn the Rust shim binary
// (test/cross-rust/shim/target/release/zkcoins-sdk-shim) to compare
// pure-JS output against the Rust reference for every randomized input.
//
// They are opt-in (`npm run test:cross`) because they require a Rust
// toolchain and a fresh `cargo build --release -p zkcoins-sdk-shim` on
// first run. CI builds the shim once per workflow and caches it.
export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['test/cross-rust/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
