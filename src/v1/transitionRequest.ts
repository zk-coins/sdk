/**
 * §7.5 `TransitionRequest` with a **closed** presence matrix for v1.
 *
 * v1 admits only cases (a) and (c): `fee_address` MUST be absent. Case (b)
 * (publisher + fee) is deferred and is not expressible in these types.
 *
 * Kind-dependent fields are mutually exclusive at the type level:
 *   send    → input_coins + output_templates
 *   mint    → output_templates + issuance
 *   receive → fold_coin_ids
 *
 * Runtime checks still enforce non-empty lists and reject a sneaked
 * `fee_address` for plain-JS callers that bypass the type checker.
 *
 * `OutputTemplate.delivery` is the closed tagged union from §7.5; unknown
 * `type` values are rejected at parse time (never passed through).
 */

import { parseDeliveryCredential, type DeliveryCredential } from './delivery.js';

export type { DeliveryCredential } from './delivery.js';

export interface OutputTemplate {
  recipient: string;
  asset_id: string;
  amount: string;
  /**
   * Delivery credential for this output slot (position binding is
   * normative: `output_templates[i].delivery` authorises only this slot).
   * Required for every non-self output; optional on self-outputs.
   */
  delivery?: DeliveryCredential;
}

export type IssuanceV1 = {
  name: string;
  decimals: number;
  issuance_version: 1;
  amount: string;
  cap_total?: never;
  terms_salt?: never;
};

export type IssuanceV2 = {
  name: string;
  decimals: number;
  issuance_version: 2;
  amount: string;
  cap_total: string;
  terms_salt: string;
};

export type Issuance = IssuanceV1 | IssuanceV2;

/**
 * Common required fields. `fee_address` is typed as `never` so any attempt to
 * set it is a TypeScript error — the only v1-legal presence cases are (a) and
 * (c), both without a fee address (api/src/jobs.rs L306–311).
 */
type TransitionBase = {
  subject: string;
  next_pubkey: string;
  npk_rand: string;
  /** Case (c): external fee-less publisher. Case (a): omit. */
  publisher_pubkey?: string;
  /** Deferred §3.8.1 — must never be set in v1. */
  fee_address?: never;
};

export type TransitionRequestSend = TransitionBase & {
  kind: 'send';
  input_coins: string[];
  output_templates: OutputTemplate[];
  fold_coin_ids?: never;
  issuance?: never;
};

export type TransitionRequestMint = TransitionBase & {
  kind: 'mint';
  output_templates: OutputTemplate[];
  issuance: Issuance;
  input_coins?: never;
  fold_coin_ids?: never;
};

export type TransitionRequestReceive = TransitionBase & {
  kind: 'receive';
  fold_coin_ids: string[];
  input_coins?: never;
  output_templates?: never;
  issuance?: never;
};

export type TransitionRequest =
  | TransitionRequestSend
  | TransitionRequestMint
  | TransitionRequestReceive;

/**
 * Runtime presence check for callers that are not type-checked.
 * Accepts `unknown` so tests and plain-JS callers can exercise the matrix
 * without TypeScript casts. Throws with a named field; never coerces.
 */
function field(obj: object, key: string): unknown {
  return Reflect.get(obj, key);
}

/**
 * Shape-level presence matrix. Does **not** run §4.3 crypto — that is
 * {@link assertTransitionRequestDeliveries} / the client's submit path,
 * which needs network + optional pin store.
 */
export function assertTransitionRequest(body: unknown): asserts body is TransitionRequest {
  if (typeof body !== 'object' || body === null) {
    throw new Error('TransitionRequest: expected object');
  }

  // Catch a fee_address that slipped past `never` via structural assignment.
  if (field(body, 'fee_address') !== undefined) {
    throw new Error(
      'TransitionRequest: fee_address must be absent in v1 (publisher presence matrix; only (a)/(c))',
    );
  }

  const subject = field(body, 'subject');
  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error('TransitionRequest: subject is required');
  }
  const nextPubkey = field(body, 'next_pubkey');
  if (typeof nextPubkey !== 'string' || nextPubkey.length === 0) {
    throw new Error('TransitionRequest: next_pubkey is required');
  }
  const npkRand = field(body, 'npk_rand');
  if (typeof npkRand !== 'string' || npkRand.length === 0) {
    throw new Error('TransitionRequest: npk_rand is required');
  }

  const kind = field(body, 'kind');
  switch (kind) {
    case 'send': {
      const inputCoins = field(body, 'input_coins');
      if (!Array.isArray(inputCoins) || inputCoins.length === 0) {
        throw new Error('TransitionRequest: kind=send requires non-empty input_coins');
      }
      const outputs = field(body, 'output_templates');
      if (!Array.isArray(outputs) || outputs.length === 0) {
        throw new Error('TransitionRequest: kind=send requires non-empty output_templates');
      }
      assertOutputTemplateShapes(outputs, 'send');
      if (field(body, 'fold_coin_ids') !== undefined) {
        throw new Error('TransitionRequest: kind=send must not carry fold_coin_ids');
      }
      if (field(body, 'issuance') !== undefined) {
        throw new Error('TransitionRequest: kind=send must not carry issuance');
      }
      break;
    }
    case 'mint': {
      const outputs = field(body, 'output_templates');
      if (!Array.isArray(outputs) || outputs.length === 0) {
        throw new Error('TransitionRequest: kind=mint requires non-empty output_templates');
      }
      assertOutputTemplateShapes(outputs, 'mint');
      const issuance = field(body, 'issuance');
      if (issuance === undefined || issuance === null) {
        throw new Error('TransitionRequest: kind=mint requires issuance');
      }
      if (field(body, 'input_coins') !== undefined) {
        throw new Error('TransitionRequest: kind=mint must not carry input_coins');
      }
      if (field(body, 'fold_coin_ids') !== undefined) {
        throw new Error('TransitionRequest: kind=mint must not carry fold_coin_ids');
      }
      if (typeof issuance !== 'object') {
        throw new Error('TransitionRequest: issuance must be an object');
      }
      const version = field(issuance, 'issuance_version');
      if (version !== 1 && version !== 2) {
        throw new Error('TransitionRequest: issuance_version must be 1 or 2');
      }
      if (version === 2) {
        if (
          field(issuance, 'cap_total') === undefined ||
          field(issuance, 'terms_salt') === undefined
        ) {
          throw new Error(
            'TransitionRequest: issuance_version=2 requires cap_total and terms_salt',
          );
        }
      }
      break;
    }
    case 'receive': {
      const fold = field(body, 'fold_coin_ids');
      if (!Array.isArray(fold) || fold.length === 0) {
        throw new Error('TransitionRequest: kind=receive requires non-empty fold_coin_ids');
      }
      if (field(body, 'input_coins') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry input_coins');
      }
      if (field(body, 'output_templates') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry output_templates');
      }
      if (field(body, 'issuance') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry issuance');
      }
      break;
    }
    default: {
      throw new Error(
        `TransitionRequest: kind must be mint|send|receive, got ${JSON.stringify(kind)}`,
      );
    }
  }
}

/**
 * Validate each output template's required fields and, when present, the
 * closed `delivery` union (unknown `type` is an error). Crypto is not run
 * here.
 */
function assertOutputTemplateShapes(outputs: unknown[], kind: string): void {
  for (let i = 0; i < outputs.length; i++) {
    const out = outputs[i];
    if (typeof out !== 'object' || out === null || Array.isArray(out)) {
      throw new Error(`TransitionRequest: kind=${kind} output_templates[${i}] must be an object`);
    }
    if (
      typeof field(out, 'recipient') !== 'string' ||
      (field(out, 'recipient') as string).length === 0
    ) {
      throw new Error(
        `TransitionRequest: kind=${kind} output_templates[${i}].recipient is required`,
      );
    }
    if (
      typeof field(out, 'asset_id') !== 'string' ||
      (field(out, 'asset_id') as string).length === 0
    ) {
      throw new Error(
        `TransitionRequest: kind=${kind} output_templates[${i}].asset_id is required`,
      );
    }
    if (typeof field(out, 'amount') !== 'string' || (field(out, 'amount') as string).length === 0) {
      throw new Error(`TransitionRequest: kind=${kind} output_templates[${i}].amount is required`);
    }
    const delivery = field(out, 'delivery');
    if (delivery !== undefined) {
      // Unknown type / wrong shape → DeliveryCredentialError (loud).
      parseDeliveryCredential(delivery);
    }
  }
}

/**
 * JSON body for `POST /v1/tx` — only defined fields, no `fee_address`, no
 * undefined-valued keys (so the server never sees `"fee_address": null`).
 */
export function transitionRequestToJson(body: TransitionRequest): Record<string, unknown> {
  assertTransitionRequest(body);
  const out: Record<string, unknown> = {
    kind: body.kind,
    subject: body.subject,
    next_pubkey: body.next_pubkey,
    npk_rand: body.npk_rand,
  };
  if (body.publisher_pubkey !== undefined) {
    out.publisher_pubkey = body.publisher_pubkey;
  }
  switch (body.kind) {
    case 'send':
      out.input_coins = body.input_coins;
      out.output_templates = body.output_templates.map(outputTemplateToJson);
      break;
    case 'mint':
      out.output_templates = body.output_templates.map(outputTemplateToJson);
      out.issuance = body.issuance;
      break;
    case 'receive':
      out.fold_coin_ids = body.fold_coin_ids;
      break;
    default: {
      const _exhaustive: never = body;
      throw new Error(`unreachable kind ${JSON.stringify(_exhaustive)}`);
    }
  }
  return out;
}

/**
 * JSON for one output template. Omits `delivery` when absent so the wire
 * never carries `"delivery": null`. When present, re-parses the closed
 * union so an unknown `type` cannot slip through.
 */
function outputTemplateToJson(t: OutputTemplate): Record<string, unknown> {
  const o: Record<string, unknown> = {
    recipient: t.recipient,
    asset_id: t.asset_id,
    amount: t.amount,
  };
  if (t.delivery !== undefined) {
    o.delivery = parseDeliveryCredential(t.delivery);
  }
  return o;
}
