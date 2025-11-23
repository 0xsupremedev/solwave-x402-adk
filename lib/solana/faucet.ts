import { Connection, Keypair, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { getSolanaConnection, getCluster } from './client';

export async function requestAirdrop(
  address: string,
  amount: number = 1 // SOL amount
): Promise<string> {
  const connection = getSolanaConnection(getCluster());
  const cluster = getCluster();

  if (cluster !== 'devnet' && cluster !== 'testnet') {
    throw new Error('Airdrops are only available on devnet and testnet');
  }

  const publicKey = new PublicKey(address);
  const signature = await connection.requestAirdrop(
    publicKey,
    amount * LAMPORTS_PER_SOL
  );

  // Wait for confirmation
  await connection.confirmTransaction(signature, 'confirmed');

  return signature;
}

export async function getBalance(address: string): Promise<number> {
  const connection = getSolanaConnection(getCluster());
  const publicKey = new PublicKey(address);
  const balance = await connection.getBalance(publicKey);
  return balance / LAMPORTS_PER_SOL; // Convert lamports to SOL
}

