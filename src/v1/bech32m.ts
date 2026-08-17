/**
 * Minimal Bech32m (BIP-350) codec for zkCoins addresses (HRP `zk`, 32-byte payload).
 *
 * Spec §1.4 / §1.7.7 / §5.1: subject is Bech32m with HRP `zk`; chal binds the
 * **raw 32-byte** address digest, not the Bech32m string.
 *
 * No third-party dependency — only this wire form is needed on the v1 surface.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHARSET_MAP: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>();
  let i = 0;
  for (const c of CHARSET) {
    m.set(c, i);
    i += 1;
  }
  return m;
})();

/** BIP-350 Bech32m constant. */
const BECH32M_CONST = 0x2bc830a3;

const ADDRESS_HRP = 'zk';
const ADDRESS_PAYLOAD_LEN = 32;

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    if (b & 1) chk ^= 0x3b6a57b2;
    if (b & 2) chk ^= 0x26508e6d;
    if (b & 4) chk ^= 0x1ea119fa;
    if (b & 8) chk ^= 0x3d4233dd;
    if (b & 16) chk ^= 0x2a1462b3;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) >>> 5);
  }
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) & 31);
  }
  return ret;
}

function createChecksum(hrp: string, data: number[]): number[] {
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ BECH32M_CONST;
  const ret: number[] = [];
  for (let p = 0; p < 6; p++) {
    ret.push((mod >>> (5 * (5 - p))) & 31);
  }
  return ret;
}

function verifyChecksum(hrp: string, data: number[]): boolean {
  return polymod(hrpExpand(hrp).concat(data)) === BECH32M_CONST;
}

/**
 * Convert between bit-widths (BIP-173 convertbits).
 *
 * Input values are produced either by a `Uint8Array` (encode: 0..255) or by the
 * Bech32 charset map (decode: 0..31) — both are dense and already range-checked
 * by construction, so a sparse/out-of-range guard is not reachable on this
 * surface and is omitted.
 *
 * `pad: true` always succeeds (encode path). `pad: false` returns `null` on
 * non-canonical residual padding (decode path).
 */
function convertBits(data: Uint8Array | number[], from: number, to: number, pad: true): number[];
function convertBits(
  data: Uint8Array | number[],
  from: number,
  to: number,
  pad: false,
): number[] | null;
function convertBits(
  data: Uint8Array | number[],
  from: number,
  to: number,
  pad: boolean,
): number[] | null {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i]!;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    /* v8 ignore next -- encodeZkAddress enforces exactly 32-byte payloads before convertBits(pad:true); 256 bits / 5 leaves remainder 1, never 0 */
    if (bits > 0) {
      ret.push((acc << (to - bits)) & maxv);
    }
    return ret;
  }
  if (bits >= from || (acc << (to - bits)) & maxv) {
    return null;
  }
  return ret;
}

/**
 * Encode 32 raw address bytes as Bech32m `zk1…`.
 */
export function encodeZkAddress(payload: Uint8Array): string {
  if (payload.length !== ADDRESS_PAYLOAD_LEN) {
    throw new Error(
      `encodeZkAddress: payload must be ${ADDRESS_PAYLOAD_LEN} bytes, got ${payload.length}`,
    );
  }
  // 8→5 with pad: overload guarantees a concrete number[] (never null).
  const data = convertBits(payload, 8, 5, true);
  const checksum = createChecksum(ADDRESS_HRP, data);
  const combined = data.concat(checksum);
  let out = `${ADDRESS_HRP}1`;
  // combined entries are 5-bit values (0..31) from convertBits + checksum.
  for (const d of combined) {
    out += CHARSET[d]!;
  }
  return out;
}

/**
 * Decode a Bech32m `zk` address to its 32-byte payload.
 * Loud on wrong HRP, checksum, or length — never silent truncation.
 */
export function decodeZkAddress(address: string): Uint8Array {
  if (typeof address !== 'string' || address.length === 0) {
    throw new Error('decodeZkAddress: empty address');
  }
  // Mixed case is forbidden by BIP-173.
  const lower = address.toLowerCase();
  if (address !== lower && address !== address.toUpperCase()) {
    throw new Error('decodeZkAddress: mixed-case Bech32m is invalid');
  }
  const s = lower;
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) {
    throw new Error('decodeZkAddress: missing separator');
  }
  const hrp = s.slice(0, pos);
  if (hrp !== ADDRESS_HRP) {
    throw new Error(
      `decodeZkAddress: expected HRP ${JSON.stringify(ADDRESS_HRP)}, got ${JSON.stringify(hrp)}`,
    );
  }
  const data: number[] = [];
  // Iterate characters directly — JS strings have no holes, so the sparse
  // index guard is unnecessary under `noUncheckedIndexedAccess`.
  for (const ch of s.slice(pos + 1)) {
    const v = CHARSET_MAP.get(ch);
    if (v === undefined) {
      throw new Error(`decodeZkAddress: invalid character ${JSON.stringify(ch)}`);
    }
    data.push(v);
  }
  if (!verifyChecksum(hrp, data)) {
    throw new Error('decodeZkAddress: checksum failed (not Bech32m or corrupted)');
  }
  const words = data.slice(0, data.length - 6);
  const bytes = convertBits(words, 5, 8, false);
  if (bytes === null) {
    throw new Error('decodeZkAddress: non-canonical padding');
  }
  if (bytes.length !== ADDRESS_PAYLOAD_LEN) {
    throw new Error(
      `decodeZkAddress: payload must be ${ADDRESS_PAYLOAD_LEN} bytes, got ${bytes.length}`,
    );
  }
  return Uint8Array.from(bytes);
}

export const ZK_ADDRESS_HRP = ADDRESS_HRP;
