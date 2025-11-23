import { X402PaymentReceipt } from './types';
import { verifyPaymentReceipt, pollTransactionConfirmation } from '../solana/verification';
import { db } from '@/lib/db/client';

export async function verifyX402Payment(
  invoiceId: string,
  txSignature: string
): Promise<X402PaymentReceipt> {
  // Get invoice
  const invoice = await db.invoice.findUnique({
    where: { id: invoiceId },
    include: {
      merchant: {
        select: {
          receivingAddress: true,
        },
      },
    },
  });

  if (!invoice) {
    throw new Error('Invoice not found');
  }

  // Poll for confirmation
  const verification = await pollTransactionConfirmation(txSignature);

  if (!verification.confirmed) {
    return {
      invoiceId,
      txSignature,
      amount: invoice.amount,
      token: invoice.token,
      confirmed: false,
    };
  }

  // Verify payment receipt
  const amount = parseFloat(invoice.amount);
  const receiptVerification = await verifyPaymentReceipt(
    txSignature,
    amount,
    invoice.merchant.receivingAddress
  );

  if (!receiptVerification.valid) {
    throw new Error(receiptVerification.error || 'Payment verification failed');
  }

  // Update invoice status
  await db.invoice.update({
    where: { id: invoiceId },
    data: {
      status: 'PAID',
      txSignature,
    },
  });

  return {
    invoiceId,
    txSignature,
    amount: invoice.amount,
    token: invoice.token,
    confirmed: true,
    confirmedAt: verification.blockTime
      ? new Date(verification.blockTime * 1000).toISOString()
      : new Date().toISOString(),
    blockTime: verification.blockTime,
  };
}

