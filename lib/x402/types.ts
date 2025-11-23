export interface X402Invoice {
  id: string;
  merchantId: string;
  amount: string;
  token: string; // Token symbol or mint address
  status: 'pending' | 'paid' | 'expired' | 'cancelled' | 'settled';
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

