import { PublicKey } from '@solana/web3.js';
import type { PaymentRequirements } from '../types/x402';

function randomHex(bytes: number): string {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(bytes);
    window.crypto.getRandomValues(arr);
    return Array.from(arr)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  // Fallback for non-browser contexts
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const nodeCrypto = require('crypto');
  return nodeCrypto.randomBytes(bytes).toString('hex');
}

// Using shared x402 PaymentRequirements

/**
 * Create x402 payment header from wallet and payment requirements
 */
export async function createPaymentHeader(
  walletPublicKey: PublicKey,
  paymentRequirements: PaymentRequirements
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const nonce = `0x${randomHex(32)}`;

  const paymentPayload = {
    x402Version: 1,
    scheme: paymentRequirements.scheme,
    network: paymentRequirements.network,
    payload: {
      signature: 'demo-signature', // In production, this would be actual transaction signature
      authorization: {
        from: walletPublicKey.toBase58(),
        to: paymentRequirements.payTo,
        value: paymentRequirements.maxAmountRequired,
        validAfter: String(nowSec - 5),
        validBefore: String(nowSec + paymentRequirements.maxTimeoutSeconds),
        nonce
      }
    }
  };

  return Buffer.from(JSON.stringify(paymentPayload)).toString('base64');
}

/**
 * Execute payment flow: request resource, create payment, verify, settle
 */
export async function executePayment(
  resourceUrl: string,
  paymentHeader: string
): Promise<{
  success: boolean;
  status: number;
  settlement?: any;
  data?: any;
  error?: string;
}> {
  try {
    // Make payment request with X-PAYMENT header
    const response = await fetch(resourceUrl, {
      headers: {
        'X-PAYMENT': paymentHeader
      }
    });

    const xPaymentResponse = response.headers.get('x-payment-response');
    const settlement = xPaymentResponse 
      ? JSON.parse(Buffer.from(xPaymentResponse, 'base64').toString('utf8'))
      : null;

    const data = response.ok ? await response.json().catch(() => null) : null;

    return {
      success: response.ok,
      status: response.status,
      settlement,
      data,
      error: response.ok ? undefined : `Payment failed: ${response.status}`
    };
  } catch (error) {
    return {
      success: false,
      status: 0,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Save transaction to localStorage for history
 */
export function saveTransactionToHistory(
  signature: string,
  resource: string,
  amount: string,
  asset: string,
  network: string,
  status: 'pending' | 'confirmed' | 'failed' = 'pending'
) {
  if (typeof window === 'undefined') return;
  
  try {
    const stored = localStorage.getItem('microapi_transactions');
    const transactions = stored ? JSON.parse(stored) : [];
    
    const newTx = {
      signature,
      timestamp: Date.now(),
      resource,
      amount,
      asset,
      network,
      status
    };
    
    transactions.unshift(newTx);
    // Keep last 50 transactions
    const limited = transactions.slice(0, 50);
    localStorage.setItem('microapi_transactions', JSON.stringify(limited));
  } catch (error) {
    console.error('Error saving transaction:', error);
  }
}

