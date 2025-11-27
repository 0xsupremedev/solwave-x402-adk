import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Keypair } from '@solana/web3.js';
import { X402SDK } from '../index';
import { KeypairSigner } from '../signers/keypairSigner';
import type { X402Invoice } from '../types/x402';

vi.mock('@solana/web3.js', async () => {
  const actual = await vi.importActual<typeof import('@solana/web3.js')>('@solana/web3.js');
  return {
    ...actual,
    Connection: class MockConnection {
      // eslint-disable-next-line class-methods-use-this
      async sendRawTransaction() {
        return 'signature';
      }
      // eslint-disable-next-line class-methods-use-this
      async getLatestBlockhash() {
        return { blockhash: 'blockhash', lastValidBlockHeight: 100 };
      }
      // eslint-disable-next-line class-methods-use-this
      async confirmTransaction() {
        return { value: { err: null } };
      }
    },
  };
});

describe('watchInvoice', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const makeSdk = () =>
    new X402SDK({
      rpcUrl: 'https://api.devnet.solana.com',
      signer: new KeypairSigner(Keypair.generate()),
      apiBaseUrl: 'https://api.example.com',
    });

  it('stops watching when stop handle is called', async () => {
    const sdk = makeSdk();
    const invoice: X402Invoice = {
      id: 'inv',
      merchantId: 'merchant',
      amount: '1',
      token: 'SOL',
      status: 'pending',
      expiresAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      nonce: 'nonce',
    };

    const spy = vi.spyOn(sdk, 'getInvoiceStatus').mockResolvedValue(invoice);

    const stop = await sdk.watchInvoice(
      'inv',
      () => {},
      { intervalMs: 100 }
    );

    vi.advanceTimersByTime(250);
    stop();
    vi.advanceTimersByTime(500);

    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('emits onError when max attempts reached', async () => {
    const sdk = makeSdk();
    vi.spyOn(sdk, 'getInvoiceStatus').mockRejectedValue(new Error('boom'));

    const onError = vi.fn();

    await sdk.watchInvoice('inv', () => {}, { intervalMs: 50, maxAttempts: 2, onError });
    vi.advanceTimersByTime(500);

    expect(onError).toHaveBeenCalled();
  });
});


