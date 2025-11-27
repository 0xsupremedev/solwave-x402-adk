import { Keypair, Connection, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { X402SDK, X402PaymentRequest } from '@solwave/x402-sdk';

async function main() {
  const rpcUrl = 'https://api.devnet.solana.com';
  const connection = new Connection(rpcUrl, 'confirmed');

  const keypair = Keypair.generate();
  console.log('Payer public key:', keypair.publicKey.toBase58());

  // Airdrop 1 SOL to the new keypair on devnet
  const sig = await connection.requestAirdrop(keypair.publicKey, 1 * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(sig, 'confirmed');
  console.log('Airdrop signature:', sig);

  const sdk = new X402SDK({
    rpcUrl,
    keypair,
  });

  const recipient = keypair.publicKey.toBase58();

  const request: X402PaymentRequest = {
    invoiceId: 'example-invoice',
    amount: '0.1',
    token: 'SOL',
    recipient,
    nonce: 'example-nonce',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  };

  const receipt = await sdk.payInvoice(request);
  console.log('Payment receipt:', receipt);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});


