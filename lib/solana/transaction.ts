import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  sendAndConfirmTransaction,
  TransactionInstruction,
} from '@solana/web3.js';
import { getTokenAccount, getOrCreateAssociatedTokenAccount, createTransferInstruction } from '@solana/spl-token';
import { getSolanaConnection, getCluster } from './client';

export interface PaymentParams {
  from: PublicKey;
  to: PublicKey;
  amount: number; // in lamports or token units
  tokenMint?: PublicKey; // If undefined, uses native SOL
  decimals?: number;
}

export async function createPaymentTransaction(
  params: PaymentParams
): Promise<Transaction> {
  const connection = getSolanaConnection(getCluster());
  const transaction = new Transaction();

  if (params.tokenMint) {
    // SPL Token transfer
    const fromTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      {} as Keypair, // This should be the payer, but we'll handle signing separately
      params.tokenMint,
      params.from
    );

    const toTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      {} as Keypair,
      params.tokenMint,
      params.to
    );

    const transferInstruction = createTransferInstruction(
      fromTokenAccount.address,
      toTokenAccount.address,
      params.from,
      BigInt(params.amount * Math.pow(10, params.decimals || 9))
    );

    transaction.add(transferInstruction);
  } else {
    // Native SOL transfer
    transaction.add(
      SystemProgram.transfer({
        fromPubkey: params.from,
        toPubkey: params.to,
        lamports: params.amount,
      })
    );
  }

  // Get recent blockhash
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = params.from;

  return transaction;
}

export async function simulateTransaction(
  transaction: Transaction,
  connection?: Connection
): Promise<{ err: any; logs: string[] }> {
  const conn = connection || getSolanaConnection(getCluster());
  const simulation = await conn.simulateTransaction(transaction);
  return {
    err: simulation.value.err,
    logs: simulation.value.logs || [],
  };
}

export async function verifyTransaction(
  signature: string,
  connection?: Connection
): Promise<boolean> {
  const conn = connection || getSolanaConnection(getCluster());
  try {
    const status = await conn.getSignatureStatus(signature);
    return status.value?.err === null && status.value?.confirmationStatus !== null;
  } catch {
    return false;
  }
}

export function getExplorerUrl(signature: string, cluster?: string): string {
  const clusterParam = cluster || getCluster();
  return `https://explorer.solana.com/tx/${signature}?cluster=${clusterParam}`;
}

