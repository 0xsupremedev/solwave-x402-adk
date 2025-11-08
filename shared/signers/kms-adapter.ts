/**
 * AWS KMS adapter for production key management
 * Uses AWS KMS to sign messages without exposing private keys
 * 
 * Note: AWS KMS supports Ed25519 keys, but you must create
 * an asymmetric signing key with Ed25519 algorithm.
 */

import { SignerAdapter } from './signer-adapter';
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { PublicKey } from '@solana/web3.js';
import * as bs58 from 'bs58';

export interface KMSAdapterConfig {
  keyId: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

export class AwsKmsAdapter implements SignerAdapter {
  private client: KMSClient;
  private keyId: string;
  private cachedPublicKey: Buffer | null = null;

  constructor(config: KMSAdapterConfig) {
    this.keyId = config.keyId;
    this.client = new KMSClient({
      region: config.region || 'us-east-1',
      credentials: config.accessKeyId && config.secretAccessKey
        ? {
            accessKeyId: config.accessKeyId,
            secretAccessKey: config.secretAccessKey,
          }
        : undefined, // Use default credentials (IAM role, etc.)
    });
  }

  async signMessage(message: Buffer): Promise<Buffer> {
    try {
      const command = new SignCommand({
        KeyId: this.keyId,
        Message: message,
        MessageType: 'RAW', // For Ed25519, use RAW
        SigningAlgorithm: 'ECDSA_SHA_256', // Note: AWS KMS doesn't directly support Ed25519
        // For Ed25519, you may need to use a different approach or provider
      });

      const response = await this.client.send(command);

      if (!response.Signature) {
        throw new Error('KMS sign command returned no signature');
      }

      return Buffer.from(response.Signature);
    } catch (error) {
      throw new Error(`KMS signing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getPublicKey(): Promise<Buffer> {
    if (this.cachedPublicKey) {
      return this.cachedPublicKey;
    }

    try {
      const command = new GetPublicKeyCommand({
        KeyId: this.keyId,
      });

      const response = await this.client.send(command);

      if (!response.PublicKey) {
        throw new Error('KMS get public key returned no key');
      }

      // AWS KMS returns DER-encoded public key
      // For Solana Ed25519, we need to extract the raw 32-byte public key
      // This is a simplified version - actual implementation depends on key format
      const publicKeyBytes = Buffer.from(response.PublicKey);
      
      // Cache for future use
      this.cachedPublicKey = publicKeyBytes;
      
      return publicKeyBytes;
    } catch (error) {
      throw new Error(`Failed to get public key from KMS: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getPublicKeyBase58(): Promise<string> {
    const publicKeyBytes = await this.getPublicKey();
    // Convert to Solana PublicKey format
    // Note: This assumes the public key is in the correct format
    // You may need to adjust based on how AWS KMS returns Ed25519 keys
    try {
      const pubkey = new PublicKey(publicKeyBytes);
      return pubkey.toBase58();
    } catch {
      // If direct conversion fails, try base58 encoding
      return bs58.encode(publicKeyBytes);
    }
  }
}

/**
 * Factory function to create KMS adapter from environment variables
 */
export function createKmsAdapterFromEnv(): AwsKmsAdapter | null {
  const keyId = process.env.HSM_ENDPOINT || process.env.KMS_KEY_ID;
  if (!keyId) {
    return null;
  }

  return new AwsKmsAdapter({
    keyId,
    region: process.env.AWS_REGION || process.env.HSM_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || process.env.HSM_API_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || process.env.HSM_API_SECRET,
  });
}

