/**
 * Signer adapters for key management
 * Export all adapters and factory functions
 */

export { SignerAdapter } from './signer-adapter';
export { LocalKeypairAdapter } from './local-keypair-adapter';
export { AwsKmsAdapter, createKmsAdapterFromEnv, type KMSAdapterConfig } from './kms-adapter';

/**
 * Factory function to create appropriate signer based on configuration
 */
import { SignerAdapter } from './signer-adapter';
import { LocalKeypairAdapter } from './local-keypair-adapter';
import { AwsKmsAdapter, createKmsAdapterFromEnv } from './kms-adapter';

export function createSignerAdapter(config: {
  type: 'local' | 'hsm' | 'kms';
  secretKey?: string;
  kmsKeyId?: string;
  kmsRegion?: string;
  kmsAccessKeyId?: string;
  kmsSecretAccessKey?: string;
}): SignerAdapter {
  switch (config.type) {
    case 'local':
      if (!config.secretKey) {
        throw new Error('secretKey is required for local signer');
      }
      return new LocalKeypairAdapter(config.secretKey);

    case 'hsm':
    case 'kms':
      if (!config.kmsKeyId) {
        // Try to create from environment
        const envAdapter = createKmsAdapterFromEnv();
        if (!envAdapter) {
          throw new Error('KMS key ID or environment variables required for KMS signer');
        }
        return envAdapter;
      }
      return new AwsKmsAdapter({
        keyId: config.kmsKeyId,
        region: config.kmsRegion,
        accessKeyId: config.kmsAccessKeyId,
        secretAccessKey: config.kmsSecretAccessKey,
      });

    default:
      throw new Error(`Unsupported signer type: ${config.type}`);
  }
}

