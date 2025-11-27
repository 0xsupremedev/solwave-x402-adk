# @0xsupremedev/x402-sdk

SolWave x402 Protocol SDK for Solana: **AI-powered agent-to-agent payments**.

This SDK provides a simple, TypeScript-first interface for creating x402 invoices, building Solana transactions, and completing payments for AI agents, merchants, and bots.

## Installation

```bash
npm install @0xsupremedev/x402-sdk @solana/web3.js
# or
pnpm add @0xsupremedev/x402-sdk @solana/web3.js
```

## Who is this for?

- **AI agents** that need to initiate and settle payments on Solana.
- **Merchants** who want x402-style invoices and receipts for their users.
- **Bot and backend developers** integrating SolWave-style payment flows.

## Quick start (Node.js)

```ts
import { Keypair } from '@solana/web3.js';
import {
  X402SDK,
  type X402PaymentRequest,
} from '@0xsupremedev/x402-sdk';

const keypair = Keypair.generate();

const sdk = new X402SDK({
  rpcUrl: 'https://api.devnet.solana.com',
  keypair,
  apiBaseUrl: 'https://your-backend.example.com', // optional, for invoice APIs
});

async function run() {
  // 1) (Optional) Create an invoice via your backend
  const invoice = await sdk.createInvoice({
    merchantId: 'merchant-123',
    amount: '1',
    token: 'USDC',
    metadata: { description: 'Test payment' },
  });

  console.log('Created invoice:', invoice);

  // 2) Build a payment request for that invoice
  const paymentRequest: X402PaymentRequest = {
    invoiceId: invoice.id,
    amount: invoice.amount,
    token: invoice.token,
    recipient: 'RecipientSolanaAddressHere',
    nonce: invoice.nonce,
    expiresAt: invoice.expiresAt,
    metadata: invoice.metadata,
  };

  // 3) Pay the invoice with the SDK keypair
  const receipt = await sdk.payInvoice(paymentRequest);
  console.log('Payment receipt:', receipt);

  // 4) Fetch the invoice status
  const current = await sdk.getInvoiceStatus(invoice.id);
  console.log('Invoice status:', current.status);
}

run().catch(console.error);
```

## Browser usage (Phantom / Solflare / etc.)

```ts
import { detectWalletAdapters, X402SDK } from '@0xsupremedev/x402-sdk';

async function initSdk() {
  const wallets = detectWalletAdapters();
  if (!wallets.length) {
    throw new Error('No browser wallet detected');
  }

  // Pick the first detected wallet (e.g., Phantom) and turn it into a signer
  const signer = wallets[0].createSigner();

  const sdk = new X402SDK({
    rpcUrl: 'https://api.devnet.solana.com',
    signer,
    apiBaseUrl: 'https://your-backend.example.com',
  });

  const invoice = await sdk.getInvoiceStatus('invoice-id');
  const receipt = await sdk.payInvoice({
    invoiceId: invoice.id,
    amount: invoice.amount,
    token: invoice.token,
    recipient: invoice.merchantId, // replace with actual recipient
    nonce: invoice.nonce,
    expiresAt: invoice.expiresAt,
  });

  console.log('Paid invoice from browser wallet', receipt);
}
```

See `examples/browser-wallet/` for a minimal Vite-friendly starter that wires a connect button and calls `detectWalletAdapters()`.

## API surface

- `class X402SDK`:
  - `constructor(config: SDKConfig)`
    - Accepts either `keypair` (Node) or a generic `signer` (wallet adapter / browser).
  - `createInvoice(params: CreateInvoiceParams): Promise<X402Invoice>`
  - `getInvoiceStatus(invoiceId: string): Promise<X402Invoice>`
  - `listInvoices(params?: ListInvoicesParams): Promise<X402Invoice[]>`
  - `watchInvoice(invoiceId, callback, options?: WatchInvoiceOptions): Promise<() => void>`
  - `buildPaymentTransaction(request: X402PaymentRequest): Promise<Transaction>`
  - `payInvoice(request: X402PaymentRequest): Promise<X402PaymentReceipt>`
  - `submitTransaction(tx: Transaction, options?: ConfirmOptions): Promise<string>`

### Types

All protocol types are exported for you to use in your apps:

- `X402Invoice`
- `X402PaymentRequest`
- `X402PaymentReceipt`
- `CreateInvoiceParams`
- `ListInvoicesParams`
- `SDKConfig`
- `WatchInvoiceOptions`
- `RetryOptions`
- `SDKLogEvent`
- `X402Signer` (signer abstraction)
- `BrowserWalletSigner`, `KeypairSigner`, and `detectWalletAdapters()` helper
- `X402Error`

All types are fully typed with TypeScript and compiled to JavaScript in `dist/` for npm consumption.

### SDKConfig fields

- `rpcUrl` – Solana RPC endpoint.
- `keypair` or `signer` – choose between a Node.js Keypair or any wallet adapter signer.
- `apiBaseUrl` / `apiKey` – optional invoice backend + auth token.
- `retry` – override default retry/backoff behavior (`maxAttempts`, `delayMs`, `backoffFactor`).
- `logger(event)` – capture structured logs (helpful for observability/audits).
- `errorHandler(error)` – centralized error reporting hook.

## Security notes

- **Key management**: never hard-code or log secret keys. For production, use a secure key management solution (HSM, KMS, or vault).
- **Networks**: start on Solana devnet, then switch `rpcUrl` to mainnet only after full testing.
- **Backend auth**: if you use `apiKey`, store it in environment variables and never commit it to source control.
- **Wallet adapters**: always request permissions explicitly from the user and handle disconnect events.
- **watchInvoice**: supply `maxDurationMs` / `maxAttempts` in `WatchInvoiceOptions` and always call the returned `stop()` handle when you no longer need updates.

## Production checklist

- [ ] Keys/signers loaded from secure storage (env vars, vault, HSM, or injected wallets).
- [ ] Configure `logger` / `errorHandler` hooks to pipe logs into your observability stack.
- [ ] Tune the `retry` strategy per environment to respect RPC rate limits.
- [ ] Use `watchInvoice` safeguards (max duration/attempts) for long-lived processes.
- [ ] Document wallet permission prompts and disconnection flows in your UI.

## Testing

- `npm test` – runs the Vitest suite (currently covering signer abstractions and transaction builders).
- Browser wallet flows require manual testing:
  1. `cd sdk/examples/browser-wallet`
  2. `npm install && npm run dev`
  3. Open the dev URL, connect Phantom/Solflare, and watch the console for receipts / retry logs.

## Roadmap & feedback

- Short-term roadmap:
  - Wallet adapter support for browser-based integrations (Phantom, Solflare, etc.).
  - Higher-level helpers for Telegram bots and agent workflows.
  - More ergonomic receipt and error handling.
- Feedback and feature requests:
  - Please open issues or pull requests in the main GitHub repo.
  - Tag SDK-related issues with `sdk` so they are easy to track.

