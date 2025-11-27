import { PublicKey } from '@solana/web3.js';
import { X402Error } from '../errors';

export function assertValidPublicKey(address: string, field: string = 'address'): PublicKey {
  try {
    return new PublicKey(address);
  } catch {
    throw new X402Error('invalid_address', `Invalid ${field}`, { address });
  }
}

export function amountToBaseUnits(amount: string, decimals: number, field: string = 'amount'): number {
  const trimmed = amount.trim();
  if (!trimmed) {
    throw new X402Error('invalid_amount', `${field} is required`, { amount });
  }

  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new X402Error('invalid_amount', `${field} must be a numeric string`, { amount });
  }

  const [whole, fraction = ''] = trimmed.split('.');
  if (fraction.length > decimals) {
    throw new X402Error(
      'amount_precision',
      `${field} has more than ${decimals} decimal places`,
      { amount, decimals }
    );
  }

  const normalized = (whole + fraction.padEnd(decimals, '0')).replace(/^0+/, '') || '0';
  const value = Number(normalized);

  if (!Number.isFinite(value) || value <= 0) {
    throw new X402Error('invalid_amount', `${field} must be greater than zero`, { amount });
  }

  if (!Number.isSafeInteger(value)) {
    throw new X402Error('amount_out_of_range', `${field} exceeds safe range`, { amount });
  }

  return value;
}


