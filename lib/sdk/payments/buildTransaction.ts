import { 
  Transaction, 
  PublicKey, 
  SystemProgram,
  Connection,
  TransactionInstruction
} from '@solana/web3.js';
import { 
  createTransferInstruction,
  getAssociatedTokenAddress,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getMint
} from '@solana/spl-token';
import { X402PaymentRequest } from '@/lib/x402/types';
import { WalletSigner } from '@/lib/sdk/wallet/signers';
import { sanitizeAddress, getTokenMint, getOrCreateATA, createATAIfNeeded } from '@/lib/sdk/utils/solana';
import { addInvoiceMemoToTransaction } from '@/lib/sdk/utils/memo';
import { validateInvoice } from './validateInvoice';
import { getSolanaConnection } from '@/lib/solana/client';

export interface BuildTransactionOptions {
  invoice: X402PaymentRequest;
  payer: PublicKey;
  connection?: Connection;
}

export interface BuildTransactionResult {
  transaction: Transaction;
  needsATA: boolean;
  ataAddress?: PublicKey;
}

/**
 * Build a Solana transaction from x402 payment request
 * Security: Recomputes all values, doesn't trust user input
 */
export async function buildTransaction(
  options: BuildTransactionOptions
): Promise<BuildTransactionResult> {
  const { invoice, payer, connection } = options;
  const conn = connection || getSolanaConnection();

  // Validate invoice first
  const validation = validateInvoice(invoice);
  if (!validation.valid) {
    throw new Error(`Invalid invoice: ${validation.errors.join(', ')}`);
  }

  // Sanitize addresses (security: don't trust input)
  const recipient = sanitizeAddress(invoice.recipient);
  const tokenMint = getTokenMint(invoice.token);

  // Create new transaction
  const transaction = new Transaction();

  // Check if this is SOL or SPL token
  const isSOL = tokenMint.equals(new PublicKey('So11111111111111111111111111111111111111112'));

  if (isSOL) {
    // SOL transfer
    const amountLamports = Math.floor(parseFloat(invoice.amount) * 1e9);
    
    transaction.add(
      SystemProgram.transfer({
        fromPubkey: payer,
        toPubkey: recipient,
        lamports: amountLamports,
      })
    );
  } else {
    // SPL token transfer
    // Security: Recompute ATA (don't trust user input)
    const { instruction: ataInstruction, ata: payerATA } = await createATAIfNeeded(
      tokenMint,
      payer,
      payer,
      conn
    );

    // Add ATA creation instruction if needed
    if (ataInstruction) {
      transaction.add(ataInstruction);
    }

    // Get or create recipient ATA
    const { instruction: recipientATAInstruction, ata: recipientATA } = await createATAIfNeeded(
      tokenMint,
      recipient,
      payer, // Payer pays for ATA creation
      conn
    );

    if (recipientATAInstruction) {
      transaction.add(recipientATAInstruction);
    }

    // Get payer ATA address
    const payerATAAddress = payerATA;

    // Convert amount to token decimals
    const mintInfo = await getMint(conn, tokenMint);
    const amount = BigInt(Math.floor(parseFloat(invoice.amount) * Math.pow(10, mintInfo.decimals)));

    // Create transfer instruction
    transaction.add(
      createTransferInstruction(
        payerATAAddress,
        recipientATA,
        payer,
        amount,
        [],
        TOKEN_PROGRAM_ID
      )
    );
  }

  // Add invoice memo (security: invoice ID in memo)
  addInvoiceMemoToTransaction(transaction, invoice.invoiceId, payer);

  // Fetch fresh blockhash
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('finalized');
  transaction.recentBlockhash = blockhash;
  transaction.lastValidBlockHeight = lastValidBlockHeight;

  // Set fee payer
  transaction.feePayer = payer;

  return {
    transaction,
    needsATA: !isSOL,
    ataAddress: !isSOL ? await getOrCreateATA(tokenMint, payer, conn) : undefined,
  };
}

/**
 * Estimate transaction fee
 */
export async function estimateTransactionFee(
  transaction: Transaction,
  connection?: Connection
): Promise<number> {
  const conn = connection || getSolanaConnection();
  
  // Get transaction size
  const serialized = transaction.serialize({
    requireAllSignatures: false,
    verifySignatures: false,
  });
  
  // Fee is based on transaction size
  // Base fee: 5000 lamports, + fee per signature (5000), + fee per byte (rent)
  const baseFee = 5000;
  const signatureFee = transaction.signatures.length * 5000;
  const sizeFee = Math.ceil(serialized.length / 1000) * 5000;
  
  return baseFee + signatureFee + sizeFee;
}

