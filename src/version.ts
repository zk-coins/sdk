/**
 * Package version, hand-mirrored from `package.json#version`.
 *
 * Hand-mirrored on purpose — reading `package.json` at runtime requires
 * either bundler-specific JSON imports, `import.meta.url` + fs, or a
 * build-time codegen step. None of these survive both Node and the
 * browser without environment-specific code. A handwritten constant is
 * the smallest cross-runtime fix.
 *
 * Kept in sync by the release process (the version bump touches both
 * `package.json` and this file as part of the same commit).
 */
export const VERSION = '0.1.1';
