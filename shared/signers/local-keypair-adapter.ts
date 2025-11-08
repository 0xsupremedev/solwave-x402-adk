/**
 * Local keypair adapter for development and testing
 * Uses in-memory keypair (not recommended for production)
 */

import { SignerAdapter } from './signer-adapter';
import * as bs58 from 'bs58';
import nacl from 'tweetnacl';
import { Keypair, PublicKey } from '@solana/web3.js';

export class LocalKeypairAdapter implements SignerAdapter {
  private keypair: Keypair;

  constructor(secretKey: string | Uint8Array) {
    if (typeof secretKey === 'string') {
      // Assume base58 encoded
      const decoded = bs58.decode(secretKey);
      this.keypair = Keypair.fromSecretKey(decoded);
    } else {
      this.keypair = Keypair.fromSecretKey(secretKey);
    }
  }

  async signMessage(message: Buffer): Promise<Buffer> {
    const signature = nacl.sign.detached(message, this.keypair.secretKey);
    return Buffer.from(signature);
  }

  async getPublicKey(): Promise<Buffer> {
    return Buffer.from(this.keypair.publicKey.toBytes());
  }

  async getPublicKeyBase58(): Promise<string> {
    return this.keypair.publicKey.toBase58();
  }

  /**
   * Get the underlying Solana Keypair (for compatibility)
   */
  getKeypair(): Keypair {
    return this.keypair;
  }
}

