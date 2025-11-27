import { PublicKey, Transaction } from '@solana/web3.js';
import type { X402Signer } from './types';

export interface SolanaWalletProvider {
  publicKey?: PublicKey | { toBase58(): string; toBytes(): Uint8Array };
  isConnected?: boolean;
  isPhantom?: boolean;
  isSolflare?: boolean;
  connect: () => Promise<{ publicKey: PublicKey } | void>;
  signTransaction: (transaction: Transaction) => Promise<Transaction>;
  signAllTransactions?: (transactions: Transaction[]) => Promise<Transaction[]>;
}

function normalizePublicKey(pk: SolanaWalletProvider['publicKey']): PublicKey | null {
  if (!pk) return null;
  if (pk instanceof PublicKey) return pk;
  if (typeof pk.toBase58 === 'function') {
    return new PublicKey(pk.toBase58());
  }
  return null;
}

export class BrowserWalletSigner implements X402Signer {
  readonly label?: string;
  private readonly provider: SolanaWalletProvider;

  constructor(provider: SolanaWalletProvider, label?: string) {
    this.provider = provider;
    this.label = label ?? 'browser-wallet';
  }

  getPublicKey(): PublicKey {
    const pk = normalizePublicKey(this.provider.publicKey);
    if (!pk) {
      throw new Error(`${this.label ?? 'wallet'} is not connected`);
    }
    return pk;
  }

  private async ensureConnected() {
    if (!this.provider.publicKey) {
      await this.provider.connect();
    }
  }

  async signTransaction(transaction: Transaction): Promise<Transaction> {
    await this.ensureConnected();
    return this.provider.signTransaction(transaction);
  }

  async signAllTransactions(transactions: Transaction[]): Promise<Transaction[]> {
    await this.ensureConnected();
    if (this.provider.signAllTransactions) {
      return this.provider.signAllTransactions(transactions);
    }

    // Fallback: sign sequentially if wallet doesn't support batch signing.
    const signed: Transaction[] = [];
    for (const tx of transactions) {
      signed.push(await this.provider.signTransaction(tx));
    }
    return signed;
  }
}


