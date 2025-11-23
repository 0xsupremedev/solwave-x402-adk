import { Connection, PublicKey } from '@solana/web3.js';
import { getSolanaConnection, getCluster } from './client';

export interface TransactionVerification {
  confirmed: boolean;
  signature: string;
  slot?: number;
  blockTime?: number;
  err?: any;
}

export async function pollTransactionConfirmation(
  signature: string,
  maxAttempts: number = 30,
  intervalMs: number = 2000
): Promise<TransactionVerification> {
  const connection = getSolanaConnection(getCluster());

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const status = await connection.getSignatureStatus(signature);

      if (status.value) {
        if (status.value.err) {
          return {
            confirmed: false,
            signature,
            err: status.value.err,
          };
        }

        if (status.value.confirmationStatus === 'confirmed' || status.value.confirmationStatus === 'finalized') {
          const tx = await connection.getTransaction(signature, {
            commitment: 'confirmed',
          });

          return {
            confirmed: true,
            signature,
            slot: status.value.slot || undefined,
            blockTime: tx?.blockTime || undefined,
          };
        }
      }

      // Wait before next attempt
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    } catch (error) {
      console.error(`Error polling transaction ${signature}:`, error);
      // Continue polling
    }
  }

  return {
    confirmed: false,
    signature,
    err: new Error('Transaction confirmation timeout'),
  };
}

export async function verifyPaymentReceipt(
  signature: string,
  expectedAmount: number,
  expectedRecipient: string
): Promise<{ valid: boolean; error?: string }> {
  const connection = getSolanaConnection(getCluster());

  try {
    const tx = await connection.getTransaction(signature, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) {
      return { valid: false, error: 'Transaction not found' };
    }

    if (tx.meta?.err) {
      return { valid: false, error: `Transaction failed: ${JSON.stringify(tx.meta.err)}` };
    }

    // Verify recipient received the expected amount
    const recipientPubkey = new PublicKey(expectedRecipient);
    const preBalances = tx.meta?.preBalances || [];
    const postBalances = tx.meta?.postBalances || [];

    // Find recipient account index
    const recipientIndex = tx.transaction.message.accountKeys.findIndex(
      (key) => key.toBase58() === expectedRecipient
    );

    if (recipientIndex === -1) {
      return { valid: false, error: 'Recipient not found in transaction' };
    }

    const balanceChange = (postBalances[recipientIndex] || 0) - (preBalances[recipientIndex] || 0);
    const expectedLamports = expectedAmount * 1e9; // Convert SOL to lamports

    if (balanceChange < expectedLamports) {
      return {
        valid: false,
        error: `Insufficient payment: expected ${expectedLamports} lamports, received ${balanceChange}`,
      };
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

