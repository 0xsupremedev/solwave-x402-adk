import { Transaction, SystemProgram, PublicKey } from '@solana/web3.js';

/**
 * Memo prefix for x402 invoice IDs
 */
export const X402_MEMO_PREFIX = 'x402:';

/**
 * Encode invoice ID into memo format
 */
export function encodeInvoiceMemo(invoiceId: string): string {
  return `${X402_MEMO_PREFIX}${invoiceId}`;
}

/**
 * Decode invoice ID from memo
 */
export function decodeInvoiceMemo(memo: string): string | null {
  if (!memo.startsWith(X402_MEMO_PREFIX)) {
    return null;
  }
  return memo.slice(X402_MEMO_PREFIX.length);
}

/**
 * Add x402 invoice memo to transaction
 * Uses Solana Memo Program
 */
export function addInvoiceMemoToTransaction(
  tx: Transaction,
  invoiceId: string,
  payer: PublicKey
): Transaction {
  const memo = encodeInvoiceMemo(invoiceId);
  // Memo program ID
  const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
  
  // Create memo instruction
  const memoInstruction = {
    programId: MEMO_PROGRAM_ID,
    keys: [
      {
        pubkey: payer,
        isSigner: true,
        isWritable: false,
      },
    ],
    data: Buffer.from(memo, 'utf8'),
  };
  
  tx.add(memoInstruction);
  return tx;
}

