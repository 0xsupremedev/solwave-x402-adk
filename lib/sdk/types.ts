export interface Invoice {
  id: string;
  merchantId: string;
  merchantName?: string;
  amount: string;
  token: string;
  status: 'pending' | 'paid' | 'expired' | 'cancelled' | 'settled';
  txSignature?: string;
  expiresAt: string;
  createdAt: string;
  metadata?: Record<string, any>;
  nonce: string;
}

export interface CreateInvoiceParams {
  merchantId: string;
  amount: string;
  token?: string;
  metadata?: Record<string, any>;
}

export interface ListInvoicesParams {
  merchantId?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

