import { Connection, Transaction, TransactionSignature, Commitment } from '@solana/web3.js';
import { getSolanaConnection } from '@/lib/solana/client';

export interface ConfirmPaymentOptions {
  signature: TransactionSignature;
  connection?: Connection;
  commitment?: Commitment;
  timeout?: number; // milliseconds
}

export interface ConfirmPaymentResult {
  confirmed: boolean;
  signature: TransactionSignature;
  slot?: number;
  blockTime?: number;
  error?: string;
}

/**
 * Submit and confirm a transaction
 * Security: Always confirm on-chain before agent acknowledgment
 */
export async function submitAndConfirmTransaction(
  transaction: Transaction,
  connection?: Connection,
  commitment: Commitment = 'finalized'
): Promise<TransactionSignature> {
  const conn = connection || getSolanaConnection();
  
  // Serialize transaction
  const serialized = transaction.serialize({
    requireAllSignatures: true,
    verifySignatures: true,
  });

  // Submit transaction
  const signature = await conn.sendRawTransaction(serialized, {
    skipPreflight: false,
    maxRetries: 3,
  });

  // Wait for confirmation
  await conn.confirmTransaction(signature, commitment);

  return signature;
}

/**
 * Confirm payment transaction
 * Waits for on-chain confirmation before returning
 */
export async function confirmPayment(
  options: ConfirmPaymentOptions
): Promise<ConfirmPaymentResult> {
  const { signature, connection, commitment = 'finalized', timeout = 60000 } = options;
  const conn = connection || getSolanaConnection();

  try {
    // Wait for confirmation with timeout
    const confirmation = await Promise.race([
      conn.confirmTransaction(signature, commitment),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Transaction confirmation timeout')), timeout)
      ),
    ]);

    // Get transaction details
    const tx = await conn.getTransaction(signature, {
      commitment,
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) {
      return {
        confirmed: false,
        signature,
        error: 'Transaction not found',
      };
    }

    return {
      confirmed: true,
      signature,
      slot: tx.slot,
      blockTime: tx.blockTime || undefined,
    };
  } catch (error: any) {
    return {
      confirmed: false,
      signature,
      error: error.message || 'Transaction confirmation failed',
    };
  }
}

/**
 * Wait for transaction confirmation with polling
 */
export async function waitForConfirmation(
  signature: TransactionSignature,
  connection?: Connection,
  commitment: Commitment = 'confirmed',
  pollInterval: number = 1000,
  maxAttempts: number = 60
): Promise<ConfirmPaymentResult> {
  const conn = connection || getSolanaConnection();

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const status = await conn.getSignatureStatus(signature);
    
    if (status?.value) {
      if (status.value.err) {
        return {
          confirmed: false,
          signature,
          error: JSON.stringify(status.value.err),
        };
      }

      if (status.value.confirmationStatus === commitment || status.value.confirmationStatus === 'finalized') {
        const tx = await conn.getTransaction(signature, {
          commitment,
          maxSupportedTransactionVersion: 0,
        });

        return {
          confirmed: true,
          signature,
          slot: tx?.slot,
          blockTime: tx?.blockTime || undefined,
        };
      }
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }

  return {
    confirmed: false,
    signature,
    error: 'Confirmation timeout',
  };
}

