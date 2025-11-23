import { 
  PublicKey, 
  Connection, 
  SystemProgram,
  LAMPORTS_PER_SOL 
} from '@solana/web3.js';
import { 
  getAssociatedTokenAddress, 
  createAssociatedTokenAccountInstruction,
  getAccount,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID
} from '@solana/spl-token';
import { getSolanaConnection } from '@/lib/solana/client';

/**
 * Validate a Solana address
 */
export function isValidAddress(address: string): boolean {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get or create associated token account address
 */
export async function getOrCreateATA(
  mint: PublicKey,
  owner: PublicKey,
  connection?: Connection
): Promise<PublicKey> {
  const conn = connection || getSolanaConnection();
  return getAssociatedTokenAddress(mint, owner, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
}

/**
 * Create instruction to create associated token account if it doesn't exist
 */
export async function createATAIfNeeded(
  mint: PublicKey,
  owner: PublicKey,
  payer: PublicKey,
  connection?: Connection
): Promise<{ instruction: any | null; ata: PublicKey }> {
  const conn = connection || getSolanaConnection();
  const ata = await getOrCreateATA(mint, owner, conn);
  
  try {
    await getAccount(conn, ata);
    // Account exists, no instruction needed
    return { instruction: null, ata };
  } catch (error: any) {
    // Account doesn't exist, create instruction
    if (error.code === 'TokenAccountNotFoundError' || error.name === 'TokenAccountNotFoundError') {
      const instruction = createAssociatedTokenAccountInstruction(
        payer,
        ata,
        owner,
        mint,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      );
      return { instruction, ata };
    }
    throw error;
  }
}

/**
 * Convert lamports to SOL
 */
export function lamportsToSol(lamports: number): number {
  return lamports / LAMPORTS_PER_SOL;
}

/**
 * Convert SOL to lamports
 */
export function solToLamports(sol: number): number {
  return Math.floor(sol * LAMPORTS_PER_SOL);
}

/**
 * Sanitize and validate a Solana address
 */
export function sanitizeAddress(address: string): PublicKey {
  try {
    return new PublicKey(address);
  } catch (error) {
    throw new Error(`Invalid Solana address: ${address}`);
  }
}

/**
 * Get well-known token mint addresses
 */
export const TOKEN_MINTS: Record<string, string> = {
  SOL: 'So11111111111111111111111111111111111111112',
  USDC: process.env.NEXT_PUBLIC_USDC_MINT || 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // Mainnet USDC
  USDT: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
};

/**
 * Get token mint address from symbol or address
 */
export function getTokenMint(symbolOrAddress: string): PublicKey {
  // If it's already a valid address, use it
  if (isValidAddress(symbolOrAddress)) {
    return new PublicKey(symbolOrAddress);
  }
  
  // Otherwise, look it up in known tokens
  const upperSymbol = symbolOrAddress.toUpperCase();
  if (TOKEN_MINTS[upperSymbol]) {
    return new PublicKey(TOKEN_MINTS[upperSymbol]);
  }
  
  throw new Error(`Unknown token: ${symbolOrAddress}`);
}

