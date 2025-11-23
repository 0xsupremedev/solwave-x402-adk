import { PublicKey, Transaction } from '@solana/web3.js';

/**
 * WalletSigner interface abstraction for wallet integration
 * This decouples SDK logic from UI wallet adapter implementation
 */
export interface WalletSigner {
  /** The public key of the wallet */
  publicKey: PublicKey;
  
  /** Sign a single transaction */
  signTransaction(tx: Transaction): Promise<Transaction>;
  
  /** Sign multiple transactions (optional, for batch operations) */
  signAllTransactions?(txs: Transaction[]): Promise<Transaction[]>;
}

/**
 * Check if an object implements the WalletSigner interface
 */
export function isWalletSigner(obj: any): obj is WalletSigner {
  return (
    obj &&
    typeof obj === 'object' &&
    obj.publicKey instanceof PublicKey &&
    typeof obj.signTransaction === 'function'
  );
}

