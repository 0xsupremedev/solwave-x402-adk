import { X402Invoice, X402PaymentRequest } from './types';
import { db } from '@/lib/db/client';
import crypto from 'crypto';

export async function createX402Invoice(
  merchantId: string,
  amount: string,
  token: string = 'USDC',
  metadata?: Record<string, any>,
  expiresInSeconds: number = 3600
): Promise<X402Invoice> {
  // Generate nonce for replay protection
  const nonce = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  const invoice = await db.invoice.create({
    data: {
      merchantId,
      amount,
      token,
      nonce,
      expiresAt,
      metadata: metadata ? JSON.stringify(metadata) : null,
      status: 'PENDING',
    },
    include: {
      merchant: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  });

  return {
    id: invoice.id,
    merchantId: invoice.merchantId,
    amount: invoice.amount,
    token: invoice.token,
    status: invoice.status.toLowerCase() as any,
    expiresAt: invoice.expiresAt.toISOString(),
    createdAt: invoice.createdAt.toISOString(),
    metadata: invoice.metadata ? JSON.parse(invoice.metadata) : undefined,
    nonce: invoice.nonce,
  };
}

export async function getX402Invoice(invoiceId: string): Promise<X402Invoice | null> {
  const invoice = await db.invoice.findUnique({
    where: { id: invoiceId },
    include: {
      merchant: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  });

  if (!invoice) return null;

  // Check if expired
  if (invoice.status === 'PENDING' && invoice.expiresAt < new Date()) {
    await db.invoice.update({
      where: { id: invoiceId },
      data: { status: 'EXPIRED' },
    });
    invoice.status = 'EXPIRED';
  }

  return {
    id: invoice.id,
    merchantId: invoice.merchantId,
    amount: invoice.amount,
    token: invoice.token,
    status: invoice.status.toLowerCase() as any,
    txSignature: invoice.txSignature || undefined,
    expiresAt: invoice.expiresAt.toISOString(),
    createdAt: invoice.createdAt.toISOString(),
    metadata: invoice.metadata ? JSON.parse(invoice.metadata) : undefined,
    nonce: invoice.nonce,
  };
}

export function createX402PaymentRequest(
  invoice: X402Invoice,
  recipientAddress: string
): X402PaymentRequest {
  return {
    invoiceId: invoice.id,
    amount: invoice.amount,
    token: invoice.token,
    recipient: recipientAddress,
    nonce: invoice.nonce,
    expiresAt: invoice.expiresAt,
    metadata: invoice.metadata,
  };
}

