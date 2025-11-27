import { describe, it, expect, vi } from 'vitest';
import { Keypair, PublicKey, Transaction } from '@solana/web3.js';
import { KeypairSigner } from '../signers/keypairSigner';
import { BrowserWalletSigner, type SolanaWalletProvider } from '../signers/browserWalletSigner';

const DUMMY_BLOCKHASH = '11111111111111111111111111111111';

function createUnsignedTransaction(feePayer: PublicKey): Transaction {
  const tx = new Transaction();
  tx.feePayer = feePayer;
  tx.recentBlockhash = DUMMY_BLOCKHASH;
  return tx;
}

describe('KeypairSigner', () => {
  it('signs transactions with the provided keypair', async () => {
    const keypair = Keypair.generate();
    const signer = new KeypairSigner(keypair);

    const tx = createUnsignedTransaction(keypair.publicKey);
    await signer.signTransaction(tx);

    const sigEntry = tx.signatures.find((signature) => signature.publicKey.equals(keypair.publicKey));
    expect(sigEntry?.signature).toBeDefined();
  });
});

describe('BrowserWalletSigner', () => {
  it('delegates signing to the underlying provider', async () => {
    const walletKeypair = Keypair.generate();
    const mockProvider: SolanaWalletProvider = {
      publicKey: walletKeypair.publicKey,
      connect: vi.fn(async () => undefined),
      signTransaction: vi.fn(async (transaction) => {
        transaction.partialSign(walletKeypair);
        return transaction;
      }),
    };

    const signer = new BrowserWalletSigner(mockProvider, 'mock-wallet');
    expect(signer.getPublicKey().toBase58()).toBe(walletKeypair.publicKey.toBase58());

    const tx = createUnsignedTransaction(walletKeypair.publicKey);
    await signer.signTransaction(tx);

    expect(mockProvider.signTransaction).toHaveBeenCalledTimes(1);
  });
});


