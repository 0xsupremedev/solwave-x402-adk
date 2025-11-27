import { describe, it, expect } from 'vitest';
import { assertValidPublicKey, amountToBaseUnits } from '../utils/validation';
import { X402Error } from '../errors';

describe('validation utils', () => {
  it('validates public keys', () => {
    const pk = assertValidPublicKey('11111111111111111111111111111111');
    expect(pk.toBase58()).toBe('11111111111111111111111111111111');
  });

  it('throws for invalid public keys', () => {
    expect(() => assertValidPublicKey('not-a-key')).toThrow(X402Error);
  });

  it('converts decimal amounts to base units', () => {
    expect(amountToBaseUnits('1.23', 2)).toBe(123);
    expect(amountToBaseUnits('0.000000001', 9)).toBe(1);
  });

  it('guards against precision overflow', () => {
    expect(() => amountToBaseUnits('0.001', 2)).toThrow(X402Error);
  });
});


