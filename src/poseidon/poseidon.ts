/**
 * Poseidon permutation (width 12) and `hash_no_pad` sponge over Goldilocks.
 *
 * Naive (readable) round structure matching
 * `plonky2::hash::poseidon::Poseidon::poseidon_naive`:
 *   full_rounds → partial_rounds_naive → full_rounds
 * with `constant_layer` + `sbox` + `mds_layer` each round.
 *
 * Sponge: `hash_n_to_hash_no_pad` in `plonky2/src/hash/hashing.rs`
 * (overwrite-mode absorb, rate 8, output 4 limbs).
 */

import { add, pow7, reduce } from './goldilocks.js';
import {
  ALL_ROUND_CONSTANTS,
  HALF_N_FULL_ROUNDS,
  MDS_MATRIX_CIRC,
  MDS_MATRIX_DIAG,
  N_PARTIAL_ROUNDS,
  SPONGE_RATE,
  SPONGE_WIDTH,
} from './constants.js';

/** Poseidon digest: four Goldilocks limbs (canonical). */
export type Digest = readonly [bigint, bigint, bigint, bigint];

export const ZERO_DIGEST: Digest = [0n, 0n, 0n, 0n];

/** `Poseidon::constant_layer` — add round constants for `roundCtr`. */
function constantLayer(state: bigint[], roundCtr: number): void {
  for (let i = 0; i < SPONGE_WIDTH; i++) {
    const rc = ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * roundCtr]!;
    state[i] = add(state[i]!, rc);
  }
}

/** `Poseidon::sbox_layer` — x⁷ on every state element. */
function sboxLayer(state: bigint[]): void {
  for (let i = 0; i < SPONGE_WIDTH; i++) {
    state[i] = pow7(state[i]!);
  }
}

/**
 * `Poseidon::mds_layer` via `mds_row_shf`:
 * row r = Σ_i state[(i+r) mod t] · CIRC[i]  +  state[r] · DIAG[r].
 */
function mdsLayer(state: readonly bigint[]): bigint[] {
  const result = new Array<bigint>(SPONGE_WIDTH);
  for (let r = 0; r < SPONGE_WIDTH; r++) {
    let acc = 0n;
    for (let i = 0; i < SPONGE_WIDTH; i++) {
      acc += state[(i + r) % SPONGE_WIDTH]! * MDS_MATRIX_CIRC[i]!;
    }
    acc += state[r]! * MDS_MATRIX_DIAG[r]!;
    result[r] = reduce(acc);
  }
  return result;
}

/** `Poseidon::full_rounds` — HALF_N_FULL_ROUNDS full rounds. */
function fullRounds(state: bigint[], roundCtr: { value: number }): void {
  for (let r = 0; r < HALF_N_FULL_ROUNDS; r++) {
    constantLayer(state, roundCtr.value);
    sboxLayer(state);
    const next = mdsLayer(state);
    for (let i = 0; i < SPONGE_WIDTH; i++) {
      state[i] = next[i]!;
    }
    roundCtr.value += 1;
  }
}

/**
 * `Poseidon::partial_rounds_naive` — only state[0] goes through the S-box.
 * Uses the same MDS as full rounds (not the FAST_PARTIAL_* optimisation).
 */
function partialRoundsNaive(state: bigint[], roundCtr: { value: number }): void {
  for (let r = 0; r < N_PARTIAL_ROUNDS; r++) {
    constantLayer(state, roundCtr.value);
    state[0] = pow7(state[0]!);
    const next = mdsLayer(state);
    for (let i = 0; i < SPONGE_WIDTH; i++) {
      state[i] = next[i]!;
    }
    roundCtr.value += 1;
  }
}

/**
 * `Poseidon::poseidon_naive` — full / partial_naive / full.
 * Corresponds to the readable path in `poseidon.rs` (not `poseidon` + FAST_*).
 */
export function poseidonPermute(input: readonly bigint[]): bigint[] {
  if (input.length !== SPONGE_WIDTH) {
    throw new RangeError(`poseidonPermute: expected width ${SPONGE_WIDTH}, got ${input.length}`);
  }
  const state = input.map((x) => reduce(x));
  const roundCtr = { value: 0 };
  fullRounds(state, roundCtr);
  partialRoundsNaive(state, roundCtr);
  fullRounds(state, roundCtr);
  return state;
}

/**
 * `PoseidonHash::hash_no_pad` / `hash_n_to_hash_no_pad`.
 * Overwrite-mode sponge: for each rate-sized chunk, overwrite state[0..len),
 * permute; then squeeze the first 4 rate elements.
 */
export function hashNoPad(inputs: readonly bigint[]): Digest {
  const state = new Array<bigint>(SPONGE_WIDTH).fill(0n);

  for (let offset = 0; offset < inputs.length; offset += SPONGE_RATE) {
    const end = offset + SPONGE_RATE < inputs.length ? offset + SPONGE_RATE : inputs.length;
    for (let j = offset; j < end; j++) {
      state[j - offset] = reduce(inputs[j]!);
    }
    const next = poseidonPermute(state);
    for (let i = 0; i < SPONGE_WIDTH; i++) {
      state[i] = next[i]!;
    }
  }

  // num_outputs = 4 ≤ RATE ⇒ single squeeze, no extra permute.
  return [state[0]!, state[1]!, state[2]!, state[3]!];
}

/** Structural equality of two digests (canonical limbs). */
export function digestsEqual(a: Digest, b: Digest): boolean {
  if (a.length !== 4 || b.length !== 4) {
    return false;
  }
  return a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];
}
