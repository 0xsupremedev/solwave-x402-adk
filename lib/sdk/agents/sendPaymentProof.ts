import { PublicKey, TransactionSignature } from '@solana/web3.js';
import { X402PaymentReceipt } from '@/lib/x402/types';

export interface PaymentProof {
  invoiceId: string;
  signature: TransactionSignature;
  payer: string; // Public key as string
  amount: string;
  token: string;
  confirmed: boolean;
  confirmedAt?: string;
  blockTime?: number;
  slot?: number;
}

/**
 * Send payment proof back to AI agent
 * This is called after on-chain confirmation
 */
export async function sendPaymentProof(
  proof: PaymentProof,
  agentEndpoint?: string
): Promise<void> {
  const endpoint = agentEndpoint || process.env.NEXT_PUBLIC_ADK_ENDPOINT || '/api/v1/agents/payment-proof';

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        invoiceId: proof.invoiceId,
        signature: proof.signature,
        payer: proof.payer,
        amount: proof.amount,
        token: proof.token,
        confirmed: proof.confirmed,
        confirmedAt: proof.confirmedAt,
        blockTime: proof.blockTime,
        slot: proof.slot,
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Failed to send payment proof' }));
      throw new Error(error.error || 'Failed to send payment proof');
    }
  } catch (error: any) {
    console.error('Error sending payment proof to agent:', error);
    // Don't throw - payment is confirmed, just logging failed
    // Agent can poll for payment status if needed
  }
}

/**
 * Convert payment proof to X402 receipt format
 */
export function proofToReceipt(proof: PaymentProof): X402PaymentReceipt {
  return {
    invoiceId: proof.invoiceId,
    txSignature: proof.signature,
    amount: proof.amount,
    token: proof.token,
    confirmed: proof.confirmed,
    confirmedAt: proof.confirmedAt,
    blockTime: proof.blockTime,
  };
}

