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
 * Hex fields are form-checked (32-byte lowercase); decimal amount strings
 * are canonical `0|[1-9][0-9]*`; issuance v1 forbids v2-only fields.
 *
 * `OutputTemplate.delivery` is the closed tagged union from §7.5; unknown
 * `type` values are rejected at parse time (never passed through).
 */

import { parseDeliveryCredential, parseU128Decimal, type DeliveryCredential } from './delivery.js';
import { decodeHexExact } from './hex.js';

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
  /** Genesis spend key Pk₀ — 32-byte lowercase hex. */
  creator_pubkey: string;
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
  /** Genesis spend key Pk₀ — 32-byte lowercase hex. */
  creator_pubkey: string;
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
  /**
   * Recipient's genesis Pk₀ — 32-byte lowercase hex. REQUIRED for a genesis
   * receive (the account's first transition); MUST be absent otherwise
   * (§7.5). Symmetric to `Issuance.creator_pubkey`.
   */
  genesis_pubkey?: string;
  input_coins?: never;
  output_templates?: never;
  issuance?: never;
};

export type TransitionRequest =
  | TransitionRequestSend
  | TransitionRequestMint
  | TransitionRequestReceive;

/**
 * Runtime presence + form check for callers that are not type-checked.
 * Accepts `unknown` so tests and plain-JS callers can exercise the matrix
 * without TypeScript casts. Throws with a named field; never coerces.
 *
 * Returns a **normalised wire object** (only defined fields, validated hex /
 * decimal strings, closed delivery unions) so a sneaked number or v2-only
 * field cannot ride through after a successful assert.
 */
export function assertTransitionRequest(body: unknown): TransitionRequest {
  if (typeof body !== 'object' || body === null) {
    throw new Error('TransitionRequest: expected object');
  }

  // Catch a fee_address that slipped past `never` via structural assignment.
  if (field(body, 'fee_address') !== undefined) {
    throw new Error(
      'TransitionRequest: fee_address must be absent in v1 (publisher presence matrix; only (a)/(c))',
    );
  }

  const subject = requireNonEmptyString(body, 'subject');
  const next_pubkey = requireHex32(body, 'next_pubkey');
  const npk_rand = requireHex32(body, 'npk_rand');

  let publisher_pubkey: string | undefined;
  if (field(body, 'publisher_pubkey') !== undefined) {
    publisher_pubkey = requireHex32(body, 'publisher_pubkey');
  }

  const kind = field(body, 'kind');
  switch (kind) {
    case 'send': {
      if (field(body, 'fold_coin_ids') !== undefined) {
        throw new Error('TransitionRequest: kind=send must not carry fold_coin_ids');
      }
      if (field(body, 'issuance') !== undefined) {
        throw new Error('TransitionRequest: kind=send must not carry issuance');
      }
      if (field(body, 'genesis_pubkey') !== undefined) {
        throw new Error('TransitionRequest: kind=send must not carry genesis_pubkey');
      }
      const input_coins = requireHex32Array(field(body, 'input_coins'), 'input_coins');
      if (input_coins.length === 0) {
        throw new Error('TransitionRequest: kind=send requires non-empty input_coins');
      }
      const outputsRaw = field(body, 'output_templates');
      if (!Array.isArray(outputsRaw) || outputsRaw.length === 0) {
        throw new Error('TransitionRequest: kind=send requires non-empty output_templates');
      }
      const output_templates = normalizeOutputTemplates(outputsRaw, 'send');
      const out: TransitionRequestSend = {
        kind: 'send',
        subject,
        next_pubkey,
        npk_rand,
        input_coins,
        output_templates,
      };
      if (publisher_pubkey !== undefined) {
        out.publisher_pubkey = publisher_pubkey;
      }
      return out;
    }
    case 'mint': {
      if (field(body, 'input_coins') !== undefined) {
        throw new Error('TransitionRequest: kind=mint must not carry input_coins');
      }
      if (field(body, 'fold_coin_ids') !== undefined) {
        throw new Error('TransitionRequest: kind=mint must not carry fold_coin_ids');
      }
      if (field(body, 'genesis_pubkey') !== undefined) {
        throw new Error('TransitionRequest: kind=mint must not carry genesis_pubkey');
      }
      const outputsRaw = field(body, 'output_templates');
      if (!Array.isArray(outputsRaw) || outputsRaw.length === 0) {
        throw new Error('TransitionRequest: kind=mint requires non-empty output_templates');
      }
      const output_templates = normalizeOutputTemplates(outputsRaw, 'mint');
      const issuanceRaw = field(body, 'issuance');
      if (issuanceRaw === undefined || issuanceRaw === null) {
        throw new Error('TransitionRequest: kind=mint requires issuance');
      }
      const issuance = normalizeIssuance(issuanceRaw);
      const out: TransitionRequestMint = {
        kind: 'mint',
        subject,
        next_pubkey,
        npk_rand,
        output_templates,
        issuance,
      };
      if (publisher_pubkey !== undefined) {
        out.publisher_pubkey = publisher_pubkey;
      }
      return out;
    }
    case 'receive': {
      if (field(body, 'input_coins') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry input_coins');
      }
      if (field(body, 'output_templates') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry output_templates');
      }
      if (field(body, 'issuance') !== undefined) {
        throw new Error('TransitionRequest: kind=receive must not carry issuance');
      }
      const fold_coin_ids = requireHex32Array(field(body, 'fold_coin_ids'), 'fold_coin_ids');
      if (fold_coin_ids.length === 0) {
        throw new Error('TransitionRequest: kind=receive requires non-empty fold_coin_ids');
      }
      let genesis_pubkey: string | undefined;
      if (field(body, 'genesis_pubkey') !== undefined) {
        genesis_pubkey = requireHex32(body, 'genesis_pubkey');
      }
      const out: TransitionRequestReceive = {
        kind: 'receive',
        subject,
        next_pubkey,
        npk_rand,
        fold_coin_ids,
      };
      if (genesis_pubkey !== undefined) {
        out.genesis_pubkey = genesis_pubkey;
      }
      if (publisher_pubkey !== undefined) {
        out.publisher_pubkey = publisher_pubkey;
      }
      return out;
    }
    default: {
      throw new Error(
        `TransitionRequest: kind must be mint|send|receive, got ${JSON.stringify(kind)}`,
      );
    }
  }
}

/**
 * JSON body for `POST /v1/tx` — only defined fields, no `fee_address`, no
 * undefined-valued keys (so the server never sees `"fee_address": null`).
 */
export function transitionRequestToJson(body: TransitionRequest): Record<string, unknown> {
  const req = assertTransitionRequest(body);
  const out: Record<string, unknown> = {
    kind: req.kind,
    subject: req.subject,
    next_pubkey: req.next_pubkey,
    npk_rand: req.npk_rand,
  };
  if (req.publisher_pubkey !== undefined) {
    out.publisher_pubkey = req.publisher_pubkey;
  }
  switch (req.kind) {
    case 'send':
      out.input_coins = req.input_coins;
      out.output_templates = req.output_templates.map(outputTemplateToJson);
      break;
    case 'mint':
      out.output_templates = req.output_templates.map(outputTemplateToJson);
      out.issuance = req.issuance;
      break;
    case 'receive':
      out.fold_coin_ids = req.fold_coin_ids;
      if (req.genesis_pubkey !== undefined) {
        out.genesis_pubkey = req.genesis_pubkey;
      }
      break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function field(obj: object, key: string): unknown {
  return Reflect.get(obj, key);
}

function requireNonEmptyString(obj: object, key: string): string {
  const v = field(obj, key);
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`TransitionRequest: ${key} is required`);
  }
  return v;
}

function requireHex32(obj: object, key: string): string {
  const v = field(obj, key);
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`TransitionRequest: ${key} is required`);
  }
  decodeHexExact(v, 32, `TransitionRequest.${key}`);
  return v;
}

function requireHex32Array(raw: unknown, fieldName: string): string[] {
  if (!Array.isArray(raw)) {
    throw new Error(`TransitionRequest: ${fieldName} must be an array`);
  }
  return raw.map((entry, i) => {
    if (typeof entry !== 'string') {
      throw new Error(`TransitionRequest: ${fieldName}[${i}] must be a 32-byte hex string`);
    }
    decodeHexExact(entry, 32, `TransitionRequest.${fieldName}[${i}]`);
    return entry;
  });
}

function normalizeOutputTemplates(outputs: unknown[], kind: string): OutputTemplate[] {
  return outputs.map((out, i) => {
    if (typeof out !== 'object' || out === null || Array.isArray(out)) {
      throw new Error(`TransitionRequest: kind=${kind} output_templates[${i}] must be an object`);
    }
    const recipient = field(out, 'recipient');
    if (typeof recipient !== 'string' || recipient.length === 0) {
      throw new Error(
        `TransitionRequest: kind=${kind} output_templates[${i}].recipient is required`,
      );
    }
    const assetId = field(out, 'asset_id');
    if (typeof assetId !== 'string' || assetId.length === 0) {
      throw new Error(
        `TransitionRequest: kind=${kind} output_templates[${i}].asset_id is required`,
      );
    }
    decodeHexExact(assetId, 32, `TransitionRequest.output_templates[${i}].asset_id`);
    const amount = field(out, 'amount');
    if (typeof amount !== 'string' || amount.length === 0) {
      throw new Error(`TransitionRequest: kind=${kind} output_templates[${i}].amount is required`);
    }
    parseU128Decimal(amount, `TransitionRequest.output_templates[${i}].amount`);
    const template: OutputTemplate = {
      recipient,
      asset_id: assetId,
      amount,
    };
    const delivery = field(out, 'delivery');
    if (delivery !== undefined) {
      // Unknown type / wrong shape → DeliveryCredentialError (loud).
      template.delivery = parseDeliveryCredential(delivery);
    }
    return template;
  });
}

function normalizeIssuance(raw: unknown): Issuance {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('TransitionRequest: issuance must be an object');
  }
  const name = field(raw, 'name');
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('TransitionRequest: issuance.name is required');
  }
  const decimals = field(raw, 'decimals');
  if (
    typeof decimals !== 'number' ||
    !Number.isInteger(decimals) ||
    decimals < 0 ||
    decimals > 255
  ) {
    throw new Error(
      'TransitionRequest: issuance.decimals must be a non-negative integer <= 255 (u8)',
    );
  }
  const amount = field(raw, 'amount');
  if (typeof amount !== 'string' || amount.length === 0) {
    throw new Error('TransitionRequest: issuance.amount is required');
  }
  parseU128Decimal(amount, 'TransitionRequest.issuance.amount');
  const creator_pubkey = field(raw, 'creator_pubkey');
  if (typeof creator_pubkey !== 'string' || creator_pubkey.length === 0) {
    throw new Error('TransitionRequest: issuance.creator_pubkey is required');
  }
  decodeHexExact(creator_pubkey, 32, 'TransitionRequest.issuance.creator_pubkey');
  const version = field(raw, 'issuance_version');
  if (version !== 1 && version !== 2) {
    throw new Error('TransitionRequest: issuance_version must be 1 or 2');
  }
  if (version === 2) {
    const cap_total = field(raw, 'cap_total');
    if (typeof cap_total !== 'string' || cap_total.length === 0) {
      throw new Error('TransitionRequest: issuance_version=2 requires cap_total and terms_salt');
    }
    parseU128Decimal(cap_total, 'TransitionRequest.issuance.cap_total');
    const terms_salt = field(raw, 'terms_salt');
    if (typeof terms_salt !== 'string' || terms_salt.length === 0) {
      throw new Error('TransitionRequest: issuance_version=2 requires cap_total and terms_salt');
    }
    decodeHexExact(terms_salt, 32, 'TransitionRequest.issuance.terms_salt');
    return {
      name,
      decimals,
      issuance_version: 2,
      amount,
      cap_total,
      terms_salt,
      creator_pubkey,
    };
  }
  // v1 — V2-only fields are explicitly forbidden (API json_to_issuance).
  if (field(raw, 'cap_total') !== undefined || field(raw, 'terms_salt') !== undefined) {
    throw new Error('TransitionRequest: issuance_version=1 must not carry cap_total or terms_salt');
  }
  return {
    name,
    decimals,
    issuance_version: 1,
    amount,
    creator_pubkey,
  };
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
