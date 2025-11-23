import { Connection, PublicKey, Cluster } from '@solana/web3.js';

const RPC_ENDPOINTS: Record<string, string> = {
  devnet: 'https://api.devnet.solana.com',
  mainnet: 'https://api.mainnet-beta.solana.com',
  testnet: 'https://api.testnet.solana.com',
};

export function getSolanaConnection(cluster: Cluster = 'devnet'): Connection {
  const endpoint = process.env.SOLANA_RPC_URL || RPC_ENDPOINTS[cluster] || RPC_ENDPOINTS.devnet;
  return new Connection(endpoint, 'confirmed');
}

export function getCluster(): Cluster {
  return (process.env.SOLANA_CLUSTER as Cluster) || 'devnet';
}

export function isValidSolanaAddress(address: string): boolean {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

