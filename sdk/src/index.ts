import { Connection, Keypair, Transaction, ConfirmOptions, SendOptions } from '@solana/web3.js';
import type {
  X402Invoice,
  X402PaymentRequest,
  X402PaymentReceipt,
  CreateInvoiceParams,
  ListInvoicesParams,
} from './types/x402';
import { buildPaymentTransaction } from './types/x402';
import type { X402Signer } from './signers/types';
import { KeypairSigner } from './signers/keypairSigner';
import { X402Error } from './errors';
import { withRetry, DEFAULT_RETRY_OPTIONS, type RetryOptions } from './utils/retry';

export * from './types/x402';
export type { X402Signer } from './signers/types';
export { KeypairSigner } from './signers/keypairSigner';
export { BrowserWalletSigner, type SolanaWalletProvider } from './signers/browserWalletSigner';
export { detectWalletAdapters, type DetectedWallet } from './signers/detect';
export { X402Error } from './errors';

/**
 * Configuration for the `X402SDK` client.
 */
export interface SDKConfig {
  /** Solana RPC URL (e.g. https://api.devnet.solana.com). */
  rpcUrl: string;
  /** Optional signer abstraction (browser wallet, Ledger, etc.). */
  signer?: X402Signer;
  /** Optional Keypair used as the default signer (Node.js convenience). */
  keypair?: Keypair;
  /**
   * Base URL of your backend that exposes x402 invoice APIs.
   * Example: https://api.yourdomain.com
   */
  apiBaseUrl?: string;
  /** Optional API key or bearer token for authenticating SDK requests. */
  apiKey?: string;
  /** Override default retry/backoff strategy. */
  retry?: Partial<RetryOptions>;
  /** Hook for centralized logging. */
  logger?: (event: SDKLogEvent) => void;
  /** Hook for centralized error handling. */
  errorHandler?: (error: X402Error) => void;
}

export interface WatchInvoiceOptions {
  intervalMs?: number;
  maxDurationMs?: number;
  maxAttempts?: number;
  onError?: (error: X402Error) => void;
}

export interface SDKLogEvent {
  level: 'info' | 'warn' | 'error';
  code: string;
  message: string;
  context?: Record<string, unknown>;
}

export class X402SDK {
  private readonly connection: Connection;
  private readonly signer: X402Signer;
  private readonly apiBaseUrl?: string;
  private readonly apiKey?: string;
  private readonly retryStrategy: RetryOptions;
  private readonly logger?: (event: SDKLogEvent) => void;
  private readonly errorHandler?: (error: X402Error) => void;

  /**
   * Create a new instance of the X402 SDK.
   *
   * @param config - Connection and backend configuration.
   */
  constructor(config: SDKConfig) {
    this.connection = new Connection(config.rpcUrl);
    const signer = config.signer ?? (config.keypair ? new KeypairSigner(config.keypair) : undefined);
    if (!signer) {
      throw new Error('X402SDK requires either a signer or a keypair');
    }
    this.signer = signer;
    this.apiBaseUrl = config.apiBaseUrl;
    this.apiKey = config.apiKey;
    this.retryStrategy = {
      ...DEFAULT_RETRY_OPTIONS,
      ...(config.retry ?? {}),
    };
    this.logger = config.logger;
    this.errorHandler = config.errorHandler;
  }

  /** Low-level HTTP helper for calling your x402 backend. */
  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    if (!this.apiBaseUrl) {
      throw new Error('apiBaseUrl is not configured on X402SDK');
    }

    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    };

    if (this.apiKey) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const endpoint = `${this.apiBaseUrl}${path}`;
    const res = await withRetry(
      () =>
        fetch(endpoint, {
          ...init,
          headers,
        }),
      this.retryStrategy,
      (_error, attempt) => {
        this.emitLog({
          level: 'warn',
          code: 'http_retry',
          message: 'Retrying HTTP request',
          context: { path, attempt },
        });
      }
    );

    if (!res.ok) {
      let errorMessage = `Request failed with status ${res.status}`;
      try {
        const body = await res.json();
        if (body && typeof body.error === 'string') {
          errorMessage = body.error;
        }
      } catch {
        // ignore JSON parse errors
      }
      const error = new X402Error('http_error', errorMessage, { path, status: res.status });
      this.emitError(error);
      throw error;
    }

    return res.json() as Promise<T>;
  }

  /**
   * Create an x402 invoice via your backend.
   * Requires `apiBaseUrl` to be configured.
   */
  async createInvoice(params: CreateInvoiceParams): Promise<X402Invoice> {
    return this.request<X402Invoice>('/api/v1/invoices', {
      method: 'POST',
      body: JSON.stringify({
        merchantId: params.merchantId,
        amount: params.amount,
        token: params.token ?? 'USDC',
        metadata: params.metadata,
      }),
    });
  }

  /** Fetch invoice status/details by ID. */
  async getInvoiceStatus(invoiceId: string): Promise<X402Invoice> {
    return this.request<X402Invoice>(`/api/v1/invoices/${invoiceId}`);
  }

  /** List invoices with optional filters (merchant, status, pagination). */
  async listInvoices(params: ListInvoicesParams = {}): Promise<X402Invoice[]> {
    const query = new URLSearchParams();
    if (params.merchantId) query.append('merchantId', params.merchantId);
    if (params.status) query.append('status', params.status);
    if (typeof params.limit === 'number') query.append('limit', params.limit.toString());
    if (typeof params.offset === 'number') query.append('offset', params.offset.toString());

    const qs = query.toString();
    const path = qs ? `/api/v1/invoices?${qs}` : '/api/v1/invoices';
    return this.request<X402Invoice[]>(path);
  }

  /**
   * Watch an invoice until it reaches a terminal state.
   *
   * Returns a function that can be called to stop watching.
   */
  async watchInvoice(
    invoiceId: string,
    callback: (invoice: X402Invoice) => void,
    options?: WatchInvoiceOptions
  ): Promise<() => void> {
    const intervalMs = options?.intervalMs ?? 2000;
    const maxDurationMs = options?.maxDurationMs ?? 5 * 60 * 1000; // default 5 minutes
    const maxAttempts = options?.maxAttempts ?? Infinity;
    const onError = options?.onError;

    let attempts = 0;
    let isWatching = true;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    const startedAt = Date.now();

    const stop = () => {
      isWatching = false;
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
    };

    const emitWatchError = (code: string, message: string, details?: Record<string, unknown>) => {
      const error = new X402Error(code, message, details);
      if (onError) {
        onError(error);
      }
      this.emitError(error);
    };

    const scheduleNext = () => {
      if (!isWatching) return;
      timeoutId = setTimeout(tick, intervalMs);
    };

    const tick = async () => {
      if (!isWatching) return;

      attempts += 1;

      try {
        const invoice = await this.getInvoiceStatus(invoiceId);
        callback(invoice);

        if (invoice.status === 'paid' || invoice.status === 'expired' || invoice.status === 'cancelled') {
          stop();
          return;
        }
      } catch (err) {
        emitWatchError('watch_invoice_request_failed', 'Failed to fetch invoice status', {
          invoiceId,
          attempt: attempts,
          cause: err instanceof Error ? err.message : String(err),
        });
      }

      if (!isWatching) return;

      if (maxAttempts !== Infinity && attempts >= maxAttempts) {
        emitWatchError('watch_invoice_max_attempts', 'Reached maximum watch attempts', {
          invoiceId,
          attempts,
        });
        stop();
        return;
      }

      if (Date.now() - startedAt >= maxDurationMs) {
        emitWatchError('watch_invoice_timeout', 'Reached maximum watch duration', {
          invoiceId,
          durationMs: Date.now() - startedAt,
        });
        stop();
        return;
      }

      scheduleNext();
    };

    void tick();

    return stop;
  }

  /**
   * Build a Solana transaction from an x402 payment request.
   *
   * This is a thin wrapper over the internal x402 transaction builder logic.
   */
  async buildPaymentTransaction(invoice: X402PaymentRequest): Promise<Transaction> {
    const payer = this.signer.getPublicKey();
    const { transaction } = await buildPaymentTransaction({
      invoice,
      payer,
      connection: this.connection,
    });
    return transaction;
  }

  /**
   * Convenience helper: pay an x402 invoice (payment request) using the
   * SDK's configured Keypair, and return a basic receipt.
   */
  async payInvoice(request: X402PaymentRequest): Promise<X402PaymentReceipt> {
    const transaction = await this.buildPaymentTransaction(request);
    const signature = await this.submitTransaction(transaction);

    return {
      invoiceId: request.invoiceId,
      txSignature: signature,
      amount: request.amount,
      token: request.token,
      confirmed: true,
      confirmedAt: new Date().toISOString(),
    };
  }

  /** Submit a signed transaction to the Solana cluster and wait for confirmation. */
  async submitTransaction(
    transaction: Transaction,
    options?: ConfirmOptions
  ): Promise<string> {
    const signedTransaction = await this.signer.signTransaction(transaction);
    const rawTransaction = signedTransaction.serialize();
    const sendOptions: SendOptions | undefined = options
      ? {
          skipPreflight: options.skipPreflight,
          preflightCommitment: options.preflightCommitment,
          maxRetries: options.maxRetries,
        }
      : undefined;

    const signature = await withRetry(
      () => this.connection.sendRawTransaction(rawTransaction, sendOptions),
      this.retryStrategy,
      (_error, attempt) => {
        this.emitLog({
          level: 'warn',
          code: 'send_raw_transaction_retry',
          message: 'Retrying sendRawTransaction',
          context: { attempt },
        });
      }
    );
    const latestBlockhash = await this.connection.getLatestBlockhash(options?.preflightCommitment ?? 'finalized');
    await this.connection.confirmTransaction(
      {
        signature,
        ...latestBlockhash,
      },
      options?.commitment ?? 'confirmed'
    );
    return signature;
  }

  private emitLog(event: SDKLogEvent) {
    this.logger?.(event);
  }

  private emitError(error: X402Error) {
    if (this.errorHandler) {
      this.errorHandler(error);
    } else {
      // eslint-disable-next-line no-console
      console.error(`[x402-sdk] ${error.code}: ${error.message}`, error.details);
    }
  }
}


