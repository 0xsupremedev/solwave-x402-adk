# Changelog

# Changelog

## 0.3.1

- Hardened `watchInvoice` with stop handles, max duration/attempt safeguards, and structured `X402Error` callbacks.
- Added address/amount validation helpers used by `buildPaymentTransaction`.
- Introduced configurable retry/backoff + logging/error hooks in `SDKConfig`.
- Expanded README with production checklist and testing guidance.
- Added new Vitest coverage for validation and watchInvoice logic.

## 0.3.0

- Added a generic `X402Signer` abstraction plus `KeypairSigner` for Node usage.
- Introduced `BrowserWalletSigner`, `detectWalletAdapters()`, and Phantom/Solflare detection helpers.
- Updated `X402SDK` to send transactions using the signer abstraction (works with wallet adapters).
- Added browser example (`examples/browser-wallet`) and documentation for wallet usage/testing.
- Added signer-focused Vitest coverage and docs on manual browser testing.

## 0.2.0

- Introduced `SDKConfig`-based constructor for `X402SDK` with `rpcUrl`, `keypair`, optional `apiBaseUrl` and `apiKey`.
- Added invoice helpers backed by your HTTP API:
  - `createInvoice`
  - `getInvoiceStatus`
  - `listInvoices`
  - `watchInvoice`
- Added `payInvoice` helper for sending SOL payments from an `X402PaymentRequest`.
- Exported protocol-level types from `sdk/src/types/x402.ts`, including:
  - `X402Invoice`, `X402PaymentRequest`, `X402PaymentReceipt`
  - `CreateInvoiceParams`, `ListInvoicesParams`.
- Added a minimal devnet example (`examples/node-devnet-example.ts`) and a `vitest` test for `buildPaymentTransaction`.

## 0.1.0

- Initial SDK scaffolding and basic transaction submission helper.


