import { describe, expect, it } from 'vitest';

import { ZKCOINS_ENDPOINTS } from '../src/networks.js';

describe('ZKCOINS_ENDPOINTS', () => {
  it('maps the two DFX-operated stages to their published URLs', () => {
    expect(ZKCOINS_ENDPOINTS.mainnet.apiUrl).toBe('https://api.zkcoins.app');
    expect(ZKCOINS_ENDPOINTS.mutinynet.apiUrl).toBe('https://dev-api.zkcoins.app');
  });

  it('attaches the matching username domain to each stage', () => {
    expect(ZKCOINS_ENDPOINTS.mainnet.usernameDomain).toBe('zkcoins.app');
    expect(ZKCOINS_ENDPOINTS.mutinynet.usernameDomain).toBe('dev.zkcoins.app');
  });

  it('mainnet runs Bitcoin mainnet, mutinynet runs the mutinynet signet', () => {
    expect(ZKCOINS_ENDPOINTS.mainnet.bitcoinNetwork).toBe('mainnet');
    expect(ZKCOINS_ENDPOINTS.mutinynet.bitcoinNetwork).toBe('mutinynet');
  });

  it('exposes only the two documented stages', () => {
    expect(Object.keys(ZKCOINS_ENDPOINTS).sort()).toEqual(['mainnet', 'mutinynet']);
  });
});
