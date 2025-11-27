import type { PublicKey, Transaction } from '@solana/web3.js';

/**
 * Minimal signer abstraction that can work with both Node Keypairs and browser wallet adapters.
 */
export interface X402Signer {
  /**
   * Human-readable label (e.g., Phantom, Solflare, Keypair). Optional.
   */
  readonly label?: string;

  /**
   * Returns the public key associated with this signer.
   */
  getPublicKey(): PublicKey;

  /**
   * Signs a single transaction and returns the signed transaction.
   */
  signTransaction(transaction: Transaction): Promise<Transaction>;

  /**
   * Optionally sign multiple transactions at once (used by some wallet adapters).
   */
  signAllTransactions?(transactions: Transaction[]): Promise<Transaction[]>;
}


