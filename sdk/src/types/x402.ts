import { assertValidPublicKey, amountToBaseUnits } from '../utils/validation';

// Lightweight copies of the x402 protocol types used in the public SDK.
// These mirror the shapes in `lib/x402/types.ts` but are self-contained so
// the npm package does not depend on the internal app code.

export type X402Status = 'pending' | 'paid' | 'expired' | 'cancelled' | 'settled';

export interface X402Invoice {
  id: string;
  merchantId: string;
  amount: string;
  token: string; // Token symbol or mint address
  status: X402Status;
  txSignature?: string;
  expiresAt: string; // ISO timestamp
  createdAt: string; // ISO timestamp
  metadata?: Record<string, any>;
  nonce: string;
}

export interface X402PaymentRequest {
  invoiceId: string;
  amount: string;
  token: string;
  recipient: string; // Solana address
  nonce: string;
  expiresAt: string;
  metadata?: Record<string, any>;
}

export interface X402PaymentReceipt {
  invoiceId: string;
  txSignature: string;
  amount: string;
  token: string;
  confirmed: boolean;
  confirmedAt?: string;
  blockTime?: number;
}

export interface CreateInvoiceParams {
  merchantId: string;
  amount: string;
  token?: string;
  metadata?: Record<string, any>;
}

export interface ListInvoicesParams {
  merchantId?: string;
  status?: X402Status;
  limit?: number;
  offset?: number;
}

export interface BuildPaymentTransactionOptions {
  invoice: X402PaymentRequest;
  payer: import('@solana/web3.js').PublicKey;
  connection?: import('@solana/web3.js').Connection;
}

export interface BuildPaymentTransactionResult {
  transaction: import('@solana/web3.js').Transaction;
}

/**
 * Public interface that mirrors the internal buildTransaction logic from `lib/sdk/payments/buildTransaction.ts`.
 * This is intentionally minimal; it focuses on assembling a payment transaction for an x402 invoice.
 */
export async function buildPaymentTransaction(
  options: BuildPaymentTransactionOptions
): Promise<BuildPaymentTransactionResult> {
  const { Connection, Transaction, SystemProgram } = await import('@solana/web3.js');

  const { invoice, payer, connection } = options;
  const conn = connection || new Connection('https://api.mainnet-beta.solana.com');

  const recipient = assertValidPublicKey(invoice.recipient, 'recipient');
  const transaction = new Transaction();

  // For now, assume native SOL payments with 9 decimals.
  // Advanced SPL token support can be added later by mirroring more of the internal logic.
  const amountLamports = amountToBaseUnits(invoice.amount, 9, 'invoice.amount');

  transaction.add(
    SystemProgram.transfer({
      fromPubkey: payer,
      toPubkey: recipient,
      lamports: amountLamports,
    })
  );

  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('finalized');
  transaction.recentBlockhash = blockhash;
  transaction.lastValidBlockHeight = lastValidBlockHeight;
  transaction.feePayer = payer;

  return { transaction };
}


