/**
 * Abstract signer adapter interface for key management
 * Supports local keypairs, HSM, KMS, and other signing providers
 */

export interface SignerAdapter {
  /**
   * Sign a message with the private key
   * @param message - Message to sign (as Buffer)
   * @returns Signature (as Buffer)
   */
  signMessage(message: Buffer): Promise<Buffer>;

  /**
   * Get the public key
   * @returns Public key (as Buffer)
   */
  getPublicKey(): Promise<Buffer>;

  /**
   * Get the public key as base58 string
   * @returns Public key as base58
   */
  getPublicKeyBase58(): Promise<string>;
}

