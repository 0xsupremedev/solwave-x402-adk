import { Keypair, PublicKey, Transaction } from '@solana/web3.js';
import type { X402Signer } from './types';

/**
 * Wraps a Keypair (Node.js) in the generic signer abstraction.
 */
export class KeypairSigner implements X402Signer {
  readonly label = 'keypair';
  private readonly keypair: Keypair;

  constructor(keypair: Keypair) {
    this.keypair = keypair;
  }

  getPublicKey(): PublicKey {
    return this.keypair.publicKey;
  }

  async signTransaction(transaction: Transaction): Promise<Transaction> {
    transaction.partialSign(this.keypair);
    return transaction;
  }

  async signAllTransactions(transactions: Transaction[]): Promise<Transaction[]> {
    transactions.forEach((tx) => tx.partialSign(this.keypair));
    return transactions;
  }
}


