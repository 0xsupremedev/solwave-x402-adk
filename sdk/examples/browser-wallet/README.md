# Browser wallet example

Tiny starter showcasing how to:

1. Detect Phantom / Solflare (or compatible) wallets injected into the browser
2. Wrap the provider in the SDK’s signer abstraction
3. Pay an invoice via the SDK

## Quick start

```bash
# from repo root
cd sdk/examples/browser-wallet
npm install
npm run dev    # start Vite/Next/etc.
```

Then open the local dev URL, click the **Connect** button, approve the wallet prompt, and watch the console log for the payment receipt. Update `src/main.ts` with your API URL / invoice IDs (the defaults use mock data).


