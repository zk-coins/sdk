/**
 * NIP-01 event id serialization + BIP-340 verify.
 *
 * Port of `node/node/src/v1/nostr/event.rs` id framing:
 *   id = SHA-256(utf8(compact_json([0, pubkey_hex, created_at, kind, tags, content])))
 *
 * String escaping (NIP-01 + RFC 8259 JSON):
 *   - classical short escapes for `"`, `\`, `\n`, `\r`, `\t`, `\b`, `\f`
 *   - remaining control characters U+0000..U+001F as `\u00xx`
 *   - every other code point (including non-ASCII / non-BMP) as raw UTF-8 —
 *     no `\uXXXX` for umlauts or emoji (the classical NIP-01 trap)
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { decodeHexExact, encodeHexLower } from './hex.js';

/** Wire shape of a canonical kind-0 (or any) NIP-01 event on the REST surface. */
export interface NostrEventJson {
  /** 32-byte event id, lowercase hex. */
  id: string;
  /** 32-byte author x-only pubkey, lowercase hex. */
  pubkey: string;
  /** Unix seconds. */
  created_at: number;
  kind: number;
  /** Array of tag arrays (NIP-01). Kind-0 typically `[]`. */
  tags: string[][];
  content: string;
  /** 64-byte BIP-340 signature under `pubkey` over `id`, lowercase hex. */
  sig: string;
}

/**
 * Escape a string under the NIP-01 id-serialization rule and wrap it in
 * double quotes. Control characters outside the seven classical short
 * escapes are emitted as `\u00xx` so the preimage is valid compact JSON.
 */
export function escapeNip01String(s: string): string {
  let out = '"';
  for (const ch of s) {
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      case '\u0008':
        out += '\\b';
        break;
      case '\u000C':
        out += '\\f';
        break;
      default: {
        const cp = ch.codePointAt(0);
        if (cp !== undefined && cp <= 0x1f) {
          out += `\\u${cp.toString(16).padStart(4, '0')}`;
        } else {
          out += ch;
        }
      }
    }
  }
  out += '"';
  return out;
}

/**
 * Canonical NIP-01 id preimage string:
 * `[0,<pubkey_hex>,<created_at>,<kind>,<tags>,<content>]` as compact JSON.
 */
export function serializeNip01IdPreimage(input: {
  pubkey: Uint8Array;
  createdAt: number;
  kind: number;
  tags: readonly (readonly string[])[];
  content: string;
}): string {
  if (input.pubkey.length !== 32) {
    throw new Error(
      `serializeNip01IdPreimage: pubkey must be 32 bytes, got ${input.pubkey.length}`,
    );
  }
  if (!Number.isInteger(input.createdAt) || input.createdAt < 0) {
    throw new Error(
      `serializeNip01IdPreimage: created_at must be a non-negative integer, got ${String(input.createdAt)}`,
    );
  }
  if (!Number.isInteger(input.kind) || input.kind < 0) {
    throw new Error(
      `serializeNip01IdPreimage: kind must be a non-negative integer, got ${String(input.kind)}`,
    );
  }

  let out = '[0,';
  out += escapeNip01String(encodeHexLower(input.pubkey));
  out += ',';
  out += String(input.createdAt);
  out += ',';
  out += String(input.kind);
  out += ',';
  out += '[';
  for (let i = 0; i < input.tags.length; i++) {
    if (i > 0) out += ',';
    const tag = input.tags[i]!;
    out += '[';
    for (let j = 0; j < tag.length; j++) {
      if (j > 0) out += ',';
      out += escapeNip01String(tag[j]!);
    }
    out += ']';
  }
  out += '],';
  out += escapeNip01String(input.content);
  out += ']';
  return out;
}

/** `id = SHA-256(utf8(serialize_id_preimage(...)))`. */
export function computeNip01EventId(input: {
  pubkey: Uint8Array;
  createdAt: number;
  kind: number;
  tags: readonly (readonly string[])[];
  content: string;
}): Uint8Array {
  const preimage = serializeNip01IdPreimage(input);
  return sha256(new TextEncoder().encode(preimage));
}

/**
 * Recompute the NIP-01 event id and verify the BIP-340 signature under the
 * author. Fail-closed: any mismatch or bad signature throws.
 */
export function verifyNip01Event(event: NostrEventJson): void {
  if (typeof event !== 'object' || event === null) {
    throw new Error('verifyNip01Event: expected object');
  }
  const pubkey = decodeHexExact(event.pubkey, 32, 'event.pubkey');
  const claimedId = decodeHexExact(event.id, 32, 'event.id');
  const sig = decodeHexExact(event.sig, 64, 'event.sig');
  if (!Array.isArray(event.tags)) {
    throw new Error('verifyNip01Event: tags must be an array');
  }
  if (typeof event.content !== 'string') {
    throw new Error('verifyNip01Event: content must be a string');
  }
  if (!Number.isInteger(event.created_at) || event.created_at < 0) {
    throw new Error(
      `verifyNip01Event: created_at must be a non-negative integer, got ${String(event.created_at)}`,
    );
  }
  if (!Number.isInteger(event.kind) || event.kind < 0) {
    throw new Error(
      `verifyNip01Event: kind must be a non-negative integer, got ${String(event.kind)}`,
    );
  }

  const tags: string[][] = [];
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || !tag.every((e) => typeof e === 'string')) {
      throw new Error('verifyNip01Event: each tag must be an array of strings');
    }
    tags.push(tag.slice());
  }

  const computed = computeNip01EventId({
    pubkey,
    createdAt: event.created_at,
    kind: event.kind,
    tags,
    content: event.content,
  });
  for (let i = 0; i < 32; i++) {
    if (computed[i] !== claimedId[i]) {
      throw new Error(
        `verifyNip01Event: event id mismatch — claimed=${encodeHexLower(claimedId)} computed=${encodeHexLower(computed)}`,
      );
    }
  }

  // BIP-340 over the 32-byte event id under the author x-only key.
  let ok: boolean;
  try {
    ok = schnorr.verify(sig, claimedId, pubkey);
  } catch {
    throw new Error('verifyNip01Event: BIP-340 verification failed (malformed key or signature)');
  }
  if (!ok) {
    throw new Error('verifyNip01Event: BIP-340 signature verification failed');
  }
}

/**
 * Sign a NIP-01 event under `secretKey` (BIP-340, zero aux-rand for
 * deterministic fixtures). Returns a fully filled {@link NostrEventJson}.
 *
 * Production callers that need non-deterministic nonces can re-sign with a
 * fresh aux-rand outside this helper; verification does not depend on it.
 */
export function signNip01Event(input: {
  secretKey: Uint8Array;
  createdAt: number;
  kind: number;
  tags: readonly (readonly string[])[];
  content: string;
}): NostrEventJson {
  if (!(input.secretKey instanceof Uint8Array) || input.secretKey.length !== 32) {
    throw new Error(
      `signNip01Event: secretKey must be 32 bytes, got ${input.secretKey?.length ?? 'invalid'}`,
    );
  }
  const pubkey = schnorr.getPublicKey(input.secretKey);
  const id = computeNip01EventId({
    pubkey,
    createdAt: input.createdAt,
    kind: input.kind,
    tags: input.tags,
    content: input.content,
  });
  const sig = schnorr.sign(id, input.secretKey, new Uint8Array(32));
  return {
    id: encodeHexLower(id),
    pubkey: encodeHexLower(pubkey),
    created_at: input.createdAt,
    kind: input.kind,
    tags: input.tags.map((t) => t.slice()),
    content: input.content,
    sig: encodeHexLower(sig),
  };
}
