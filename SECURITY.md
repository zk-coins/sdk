# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in zkCoins, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email: security@zkcoins.app
3. Include: description, reproduction steps, impact assessment
4. We will acknowledge within 48 hours and provide a fix timeline

## Scope

| Component                              | In Scope |
| -------------------------------------- | -------- |
| Key derivation (BIP-39 / BIP-32)       | Yes      |
| Schnorr signing (BIP-340)              | Yes      |
| REST client / node communication       | Yes      |
| High-level account adapter             | Yes      |
| Examples                               | No       |
| Node backend (see [zk-coins/node](https://github.com/zk-coins/node)) | Report there |

## Supported Versions

Only the latest published `@zkcoins/sdk` release and the current `develop` branch are supported with security updates.

## Responsible Disclosure

We follow a 90-day disclosure policy. After reporting, we will:

1. Confirm the vulnerability within 48 hours
2. Develop and test a fix
3. Release the fix
4. Credit the reporter (unless they prefer anonymity)
