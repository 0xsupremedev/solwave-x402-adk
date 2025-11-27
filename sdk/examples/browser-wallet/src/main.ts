import {
  detectWalletAdapters,
  X402SDK,
  type X402PaymentRequest,
} from '@0xsupremedev/x402-sdk';

async function connectWallet() {
  const wallets = detectWalletAdapters();
  if (!wallets.length) {
    throw new Error('No Solana wallet detected');
  }

  const signer = wallets[0].createSigner();
  const sdk = new X402SDK({
    rpcUrl: 'https://api.devnet.solana.com',
    signer,
    apiBaseUrl: 'https://your-backend.example.com',
  });

  // Example payment request – replace with real invoice data.
  const paymentRequest: X402PaymentRequest = {
    invoiceId: 'demo-invoice',
    amount: '0.01',
    token: 'SOL',
    recipient: signer.getPublicKey().toBase58(),
    nonce: 'demo-nonce',
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  };

  const receipt = await sdk.payInvoice(paymentRequest);
  console.log('Paid invoice from browser wallet:', receipt);
}

document.getElementById('connect')?.addEventListener('click', () => {
  connectWallet().catch((err) => {
    console.error(err);
    alert(err instanceof Error ? err.message : String(err));
  });
});


