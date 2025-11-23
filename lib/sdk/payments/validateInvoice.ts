import { PublicKey } from '@solana/web3.js';
import { X402PaymentRequest } from '@/lib/x402/types';
import { sanitizeAddress, getTokenMint } from '@/lib/sdk/utils/solana';

export interface InvoiceValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate x402 payment request/invoice
 * Security: Validate all fields, don't trust user input
 */
export function validateInvoice(invoice: X402PaymentRequest): InvoiceValidationResult {
  const errors: string[] = [];

  // Validate invoice ID
  if (!invoice.invoiceId || typeof invoice.invoiceId !== 'string' || invoice.invoiceId.trim().length === 0) {
    errors.push('Invoice ID is required');
  }

  // Validate amount
  if (!invoice.amount || typeof invoice.amount !== 'string') {
    errors.push('Amount is required');
  } else {
    const amountNum = parseFloat(invoice.amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      errors.push('Amount must be a positive number');
    }
  }

  // Validate token
  if (!invoice.token || typeof invoice.token !== 'string') {
    errors.push('Token is required');
  } else {
    try {
      getTokenMint(invoice.token);
    } catch (error: any) {
      errors.push(`Invalid token: ${error.message}`);
    }
  }

  // Validate recipient address
  if (!invoice.recipient || typeof invoice.recipient !== 'string') {
    errors.push('Recipient address is required');
  } else {
    try {
      sanitizeAddress(invoice.recipient);
    } catch (error: any) {
      errors.push(`Invalid recipient address: ${error.message}`);
    }
  }

  // Validate nonce
  if (!invoice.nonce || typeof invoice.nonce !== 'string' || invoice.nonce.trim().length === 0) {
    errors.push('Nonce is required');
  }

  // Validate expiry
  if (!invoice.expiresAt) {
    errors.push('Expiry timestamp is required');
  } else {
    const expiryTime = typeof invoice.expiresAt === 'string' 
      ? new Date(invoice.expiresAt).getTime()
      : parseInt(invoice.expiresAt.toString());
    
    if (isNaN(expiryTime)) {
      errors.push('Invalid expiry timestamp format');
    } else if (expiryTime < Date.now()) {
      errors.push('Invoice has expired');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Check if invoice is expired
 */
export function isInvoiceExpired(invoice: X402PaymentRequest): boolean {
  if (!invoice.expiresAt) return true;
  
  const expiryTime = typeof invoice.expiresAt === 'string'
    ? new Date(invoice.expiresAt).getTime()
    : parseInt(invoice.expiresAt.toString());
  
  return !isNaN(expiryTime) && expiryTime < Date.now();
}

/**
 * Validate amount matches expected value
 */
export function validateAmount(actual: string, expected: string, tolerance: number = 0.0001): boolean {
  const actualNum = parseFloat(actual);
  const expectedNum = parseFloat(expected);
  
  if (isNaN(actualNum) || isNaN(expectedNum)) {
    return false;
  }
  
  return Math.abs(actualNum - expectedNum) <= tolerance;
}

/**
 * Validate token mint matches expected
 */
export function validateTokenMint(actual: string, expected: string): boolean {
  try {
    const actualMint = getTokenMint(actual);
    const expectedMint = getTokenMint(expected);
    return actualMint.equals(expectedMint);
  } catch {
    return false;
  }
}

