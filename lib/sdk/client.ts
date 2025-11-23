import { PublicKey, Connection } from '@solana/web3.js';
import { WalletSigner } from './wallet/signers';
import { buildTransaction, BuildTransactionOptions } from './payments/buildTransaction';
import { submitAndConfirmTransaction, confirmPayment } from './payments/confirmPayment';
import { sendPaymentProof, PaymentProof } from './agents/sendPaymentProof';
import { X402PaymentRequest } from '@/lib/x402/types';
import { getSolanaConnection } from '@/lib/solana/client';

export interface SDKConfig {
  apiUrl?: string;
  apiKey?: string;
  connection?: Connection;
}

export class X402SDK {
  private apiUrl: string;
  private apiKey?: string;
  private connection: Connection;

  constructor(config: SDKConfig = {}) {
    this.apiUrl = config.apiUrl || process.env.NEXT_PUBLIC_API_URL || 'https://api.yourdomain.com';
    this.apiKey = config.apiKey;
    this.connection = config.connection || getSolanaConnection();
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(`${this.apiUrl}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || 'Request failed');
    }

    return response.json();
  }

  async createInvoice(params: {
    merchantId: string;
    amount: string;
    token?: string;
    metadata?: Record<string, any>;
  }) {
    return this.request('/api/v1/invoices', {
      method: 'POST',
      body: JSON.stringify({
        merchantId: params.merchantId,
        amount: params.amount,
        token: params.token || 'USDC',
        metadata: params.metadata,
      }),
    });
  }

  async getInvoice(invoiceId: string) {
    return this.request(`/api/v1/invoices/${invoiceId}`);
  }

  async watchInvoice(
    invoiceId: string,
    callback: (invoice: any) => void,
    interval: number = 2000
  ): Promise<() => void> {
    let isWatching = true;

    const checkStatus = async () => {
      if (!isWatching) return;

      try {
        const invoice = await this.getInvoice(invoiceId);
        callback(invoice);

        if (invoice.status === 'paid' || invoice.status === 'expired' || invoice.status === 'cancelled') {
          isWatching = false;
          return;
        }
      } catch (error) {
        console.error('Error watching invoice:', error);
      }

      if (isWatching) {
        setTimeout(checkStatus, interval);
      }
    };

    checkStatus();

    return () => {
      isWatching = false;
    };
  }

  async listInvoices(params?: {
    merchantId?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.merchantId) queryParams.append('merchantId', params.merchantId);
    if (params?.status) queryParams.append('status', params.status);
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.offset) queryParams.append('offset', params.offset.toString());

    return this.request(`/api/v1/invoices?${queryParams.toString()}`);
  }

  /**
   * Build payment transaction from x402 invoice
   * Requires wallet signer
   */
  async buildPaymentTransaction(
    invoice: X402PaymentRequest,
    signer: WalletSigner
  ) {
    return buildTransaction({
      invoice,
      payer: signer.publicKey,
      connection: this.connection,
    });
  }

  /**
   * Pay with wallet - complete payment flow
   */
  async payWithWallet(
    invoice: X402PaymentRequest,
    signer: WalletSigner
  ): Promise<PaymentProof> {
    // Build transaction
    const { transaction } = await buildTransaction({
      invoice,
      payer: signer.publicKey,
      connection: this.connection,
    });

    // Sign transaction
    const signedTx = await signer.signTransaction(transaction);

    // Submit and confirm
    const signature = await submitAndConfirmTransaction(signedTx, this.connection);

    // Wait for confirmation
    const confirmation = await confirmPayment({
      signature,
      connection: this.connection,
    });

    if (!confirmation.confirmed) {
      throw new Error(confirmation.error || 'Transaction confirmation failed');
    }

    // Build payment proof
    const proof: PaymentProof = {
      invoiceId: invoice.invoiceId,
      signature,
      payer: signer.publicKey.toBase58(),
      amount: invoice.amount,
      token: invoice.token,
      confirmed: true,
      confirmedAt: new Date().toISOString(),
      blockTime: confirmation.blockTime,
      slot: confirmation.slot,
    };

    // Send proof to agent
    await sendPaymentProof(proof);

    return proof;
  }
}

export function createSDK(config?: SDKConfig): X402SDK {
  return new X402SDK(config);
}

