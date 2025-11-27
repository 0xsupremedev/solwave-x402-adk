import { describe, it, expect } from 'vitest';
import { PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import { buildPaymentTransaction, X402PaymentRequest } from '../types/x402';

describe('buildPaymentTransaction', () => {
  it('builds a SOL transfer transaction with correct fee payer', async () => {
    const payer = new PublicKey('So11111111111111111111111111111111111111112');
    const recipient = new PublicKey('8N4N4qgHn16BQS4w7u8f1ZcY5JgcnZ6Fjt5Z7V7z2v2S');

    const invoice: X402PaymentRequest = {
      invoiceId: 'inv-1',
      amount: '0.5',
      token: 'SOL',
      recipient: recipient.toBase58(),
      nonce: 'nonce',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    // Stub connection so we don't hit a real RPC endpoint
    const stubConnection = {
      getLatestBlockhash: async () => ({
        blockhash: 'dummy-blockhash',
        // use a plain number to avoid BigInt requirement on older targets
        lastValidBlockHeight: 123 as any,
      }),
    } as any;

    const { transaction } = await buildPaymentTransaction({
      invoice,
      payer,
      connection: stubConnection,
    });

    expect(transaction).toBeInstanceOf(Transaction);
    expect(transaction.feePayer?.toBase58()).toBe(payer.toBase58());

    const ix = transaction.instructions.find(
      (i) => i.programId.equals(SystemProgram.programId)
    );
    expect(ix).toBeDefined();
  });
});



