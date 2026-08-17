/**
 * Strict lowercase hex helpers for the v1 wire surface (§7.1 / node signature.rs).
 *
 * Alphabet: ASCII `0-9` `a-f` only. No `0x` prefix, no whitespace, no uppercase.
 * Wrong length or alphabet is a loud error — never pad/truncate.
 */

const HEX_BYTE = /^(?:[0-9a-f]{2})+$/;

export function encodeHexLower(bytes: Uint8Array): string {
  // `for…of` over a Uint8Array yields `number` (not `number | undefined`), so
  // the sparse-index guard that `noUncheckedIndexedAccess` would force on
  // `bytes[i]` is unnecessary — TypedArrays have no holes.
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

export function decodeHexExact(hex: string, byteLen: number, field: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new Error(`${field}: expected hex string`);
  }
  if (hex.length !== byteLen * 2) {
    throw new Error(`${field}: expected ${byteLen * 2} hex chars, got ${hex.length}`);
  }
  if (!HEX_BYTE.test(hex)) {
    throw new Error(
      `${field}: non-canonical hex (must be lowercase 0-9a-f only, no 0x/whitespace)`,
    );
  }
  const out = new Uint8Array(byteLen);
  for (let i = 0; i < byteLen; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Constant-time-ish equality for equal-length digests (fail-closed on length). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    // Both lengths match and TypedArrays have no holes — index is in range.
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
