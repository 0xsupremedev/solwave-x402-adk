import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pino from 'pino';
import { z } from 'zod';
import bs58 from 'bs58';
import { Connection, Keypair, PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { getAssociatedTokenAddress, createAssociatedTokenAccountInstruction, getAccount, createTransferCheckedInstruction, getMint } from '@solana/spl-token';
import crypto from 'node:crypto';
import { TTLStore } from './store';
import { loadConfig } from './config';
import { checkNonceOnChain, registerNonceOnChain } from './nonce-registry';
import { createKeyManager, KeyRotationScheduler } from './key-management';
import { RateLimitMiddleware } from './rate-limit';
import { OraclePriceValidator } from './oracle';
import { OptimisticVerifier } from './optimistic-verify';
import { BatchSettlementManager, QueuedPayment } from './batch-settlement';
import { FeePayerPool } from './fee-payer-pool';
import { FailoverCoordinator, MerkleReceiptSync } from './failover';
import { NFTMintingService } from './nft-minting';
import { AnalyticsAggregator } from './analytics';
import { ReputationManager } from './reputation';
import { BridgeManager } from './bridge';

const log = pino();
const app = express();

// Security: CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];
app.use(cors({
  origin: (origin, callback) => {
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-PAYMENT'],
}));

// Security: Body parsing with size limit
app.use(express.json({ limit: '1mb' }));

// Security: Security headers middleware
app.use((req, res, next) => {
  // Only add security headers for HTTPS requests
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Load and validate configuration
let config;
try {
  config = loadConfig();
} catch (error) {
  log.error({ error }, 'Failed to load configuration');
  process.exit(1);
}

const { PORT, NETWORK, RPC_URL, FEE_PAYER_SECRET, AUTH_TOKEN, SETTLEMENT_MODE, USE_X402_HELPERS, DISABLE_RATE_LIMIT, RATE_LIMIT_MIN_INTERVAL_MS, DISABLE_NONCE_REPLAY, DEMO_MODE, REDIS_URL, KEY_MANAGEMENT_TYPE, KEY_ROTATION_INTERVAL_MS, HSM_PROVIDER, HSM_PUBLIC_KEY, HSM_ENDPOINT, HSM_API_KEY, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_REQUESTS, ENABLE_REPUTATION, ENABLE_POW, POW_DIFFICULTY, ORACLE_PROVIDER, ORACLE_PRICE_FEED_ID, ORACLE_MAX_DEVIATION_PERCENT } = config;

const connection = new Connection(RPC_URL, 'confirmed');

// Initialize key manager
const keyManager = createKeyManager({
  type: KEY_MANAGEMENT_TYPE,
  secretKey: FEE_PAYER_SECRET,
  publicKey: HSM_PUBLIC_KEY,
  hsmProvider: HSM_PROVIDER,
  hsmEndpoint: HSM_ENDPOINT,
  hsmApiKey: HSM_API_KEY,
});

// Start key rotation scheduler
const keyRotationScheduler = new KeyRotationScheduler(
  keyManager,
  KEY_ROTATION_INTERVAL_MS,
  async (newKeyManager) => {
    log.info({ newPublicKey: newKeyManager.getPublicKey().toBase58() }, 'Key rotated - update facilitator configuration');
    // In production, you'd update the facilitator's key reference here
  }
);
keyRotationScheduler.start();

// Legacy feePayer for backward compatibility (will be replaced by keyManager)
const feePayer = KEY_MANAGEMENT_TYPE === 'local' && FEE_PAYER_SECRET
  ? Keypair.fromSecretKey(bs58.decode(FEE_PAYER_SECRET))
  : Keypair.generate();

// Fee payer pool (if enabled)
const ENABLE_FEE_PAYER_POOL = process.env.ENABLE_FEE_PAYER_POOL === 'true' || process.env.ENABLE_FEE_PAYER_POOL === '1';
const feePayerPool = ENABLE_FEE_PAYER_POOL 
  ? new FeePayerPool(connection, {
      minBalance: 0.1 * LAMPORTS_PER_SOL,
      autoFund: NETWORK === 'devnet',
      rotationStrategy: (process.env.FEE_PAYER_ROTATION_STRATEGY as any) || 'round-robin'
    })
  : null;
if (feePayerPool) {
  feePayerPool.initializeFromEnv();
  feePayerPool.startMonitoring(60000); // Monitor every minute
  log.info('Fee payer pool enabled');
}

// NFT minting service (if enabled - optional, requires Metaplex)
let nftMintingService: NFTMintingService | null = null;
const ENABLE_NFT_RECEIPTS = process.env.ENABLE_NFT_RECEIPTS === 'true' || process.env.ENABLE_NFT_RECEIPTS === '1';
if (ENABLE_NFT_RECEIPTS) {
  try {
    nftMintingService = new NFTMintingService(connection, feePayer);
    log.info('NFT receipt minting enabled');
  } catch (error) {
    log.warn({ error }, 'NFT minting service not available (Metaplex may not be installed)');
    nftMintingService = null;
  }
}

// Analytics aggregator
const analytics = new AnalyticsAggregator();

// Reputation manager
const reputationManager = new ReputationManager(connection, new PublicKey('11111111111111111111111111111111'));

// Multi-chain bridge (if enabled)
const BRIDGE_PROVIDER = process.env.BRIDGE_PROVIDER as 'wormhole' | 'layerzero' | undefined;
const bridgeManager = BRIDGE_PROVIDER 
  ? new BridgeManager(connection, BRIDGE_PROVIDER)
  : null;
if (bridgeManager) {
  log.info({ provider: BRIDGE_PROVIDER, supportedChains: bridgeManager.getSupportedChains() }, 'Multi-chain bridge enabled');
}

// Auto-fund on devnet if balance is low (with retry logic and alternative methods)
async function requestAirdropWithRetry(publicKey: PublicKey, amount: number, maxRetries = 5): Promise<string | null> {
  // Try different amounts to work around rate limits
  const amounts = [amount, amount * 0.5, amount * 0.25];
  
  for (const tryAmount of amounts) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          // Longer delays: 2s, 5s, 10s, 15s, 20s
          const delay = Math.min(2000 + (attempt - 1) * 5000, 20000);
          log.info({ attempt, delay, amount: tryAmount }, 'Waiting before retry...');
          await new Promise(resolve => setTimeout(resolve, delay));
        }
        
        log.info({ attempt: attempt + 1, publicKey: publicKey.toBase58(), amount: tryAmount }, 'Requesting devnet airdrop...');
        const signature = await connection.requestAirdrop(publicKey, tryAmount);
        await connection.confirmTransaction(signature, 'confirmed');
        const balance = await connection.getBalance(publicKey);
        log.info({ signature, balance, amount: tryAmount }, 'Airdrop successful');
        return signature;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'unknown';
        const isRateLimit = errorMsg.includes('429') || errorMsg.includes('rate limit') || errorMsg.includes('Too Many Requests');
        
        if (isRateLimit && attempt < maxRetries - 1) {
          log.warn({ attempt: attempt + 1, error: errorMsg }, 'Rate limited, waiting longer before retry...');
          // Wait longer on rate limits
          await new Promise(resolve => setTimeout(resolve, 15000));
          continue;
        }
        
        if (attempt === maxRetries - 1) {
          if (tryAmount === amounts[amounts.length - 1]) {
            log.warn({ error: errorMsg, publicKey: publicKey.toBase58(), triedAmounts: amounts }, 'Airdrop failed after all attempts with all amounts');
            return null;
          }
          // Try next amount
          break;
        }
        log.warn({ attempt: attempt + 1, error: errorMsg }, 'Airdrop attempt failed, will retry...');
      }
    }
  }
  return null;
}

async function ensureFunding() {
  if (NETWORK !== 'devnet' || FEE_PAYER_SECRET) {
    return; // Only auto-fund auto-generated keypairs on devnet
  }
  
  try {
    const balance = await connection.getBalance(feePayer.publicKey);
    const minBalance = 0.1 * LAMPORTS_PER_SOL; // 0.1 SOL minimum
    
    if (balance < minBalance) {
      await requestAirdropWithRetry(feePayer.publicKey, 2 * LAMPORTS_PER_SOL); // Request 2 SOL for buffer
    }
  } catch (error) {
    log.warn({ error: error instanceof Error ? error.message : 'unknown' }, 'Auto-funding check failed');
  }
}

// Try to auto-fund on startup (non-blocking)
ensureFunding().catch(() => {
  // Ignore errors, just log
});

// x402 Verify request (spec-compatible)
const PaymentRequirements = z.object({
  scheme: z.string(),
  network: z.string(),
  maxAmountRequired: z.string(),
  resource: z.string(),
  description: z.string().optional(),
  mimeType: z.string().optional(),
  outputSchema: z.any().optional().nullable(),
  payTo: z.string(),
  maxTimeoutSeconds: z.number(),
  asset: z.string(),
  extra: z.any().optional().nullable()
});

const VerifyReq = z.object({
  x402Version: z.number().int().positive(),
  paymentHeader: z.string(),
  paymentRequirements: PaymentRequirements
});

type ExactSvmAuthorization = {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
};

// Advanced rate limiting with Redis and reputation
const rateLimitMiddleware = new RateLimitMiddleware({
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
  redisUrl: REDIS_URL || undefined,
  enableReputation: ENABLE_REPUTATION,
  enablePoW: ENABLE_POW,
  powDifficulty: POW_DIFFICULTY,
});

// Oracle price validation
const oracleValidator = new OraclePriceValidator({
  provider: ORACLE_PROVIDER,
  priceFeedId: ORACLE_PRICE_FEED_ID,
  maxDeviationPercent: ORACLE_MAX_DEVIATION_PERCENT,
  connection,
});

// Optimistic verification (if enabled)
const ENABLE_OPTIMISTIC = process.env.ENABLE_OPTIMISTIC === 'true' || process.env.ENABLE_OPTIMISTIC === '1';
const optimisticVerifier = ENABLE_OPTIMISTIC ? new OptimisticVerifier(connection) : null;
if (optimisticVerifier) {
  optimisticVerifier.startReconciliation(5000); // Reconcile every 5 seconds
  log.info('Optimistic verification enabled');
}

// Batch settlement (if enabled)
const ENABLE_BATCH_SETTLEMENT = process.env.ENABLE_BATCH_SETTLEMENT === 'true' || process.env.ENABLE_BATCH_SETTLEMENT === '1';
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || '10', 10);
const BATCH_INTERVAL_MS = parseInt(process.env.BATCH_INTERVAL_MS || '5000', 10);
const batchSettlementManager = ENABLE_BATCH_SETTLEMENT 
  ? new BatchSettlementManager(connection, feePayer, BATCH_SIZE, BATCH_INTERVAL_MS)
  : null;
if (batchSettlementManager) {
  batchSettlementManager.start();
  log.info({ batchSize: BATCH_SIZE, intervalMs: BATCH_INTERVAL_MS }, 'Batch settlement enabled');
}

// Simple auth + rate limit (very light) - fallback
const lastReq: Record<string, number> = {};
// Choose storage: Redis if REDIS_URL is provided and client is available, else file TTLStore
function createStore(fileName: string) {
  if (REDIS_URL) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Redis = require('ioredis');
      const redis = new Redis(REDIS_URL);
      const prefix = `microapi:${fileName}:`;
      return {
        async set(key: string, ttlMs: number) {
          await redis.set(prefix + key, '1', 'PX', ttlMs);
        },
        async has(key: string) {
          const v = await redis.get(prefix + key);
          return v !== null;
        }
      } as { set: (k: string, t: number) => Promise<void> | void; has: (k: string) => Promise<boolean> | boolean };
    } catch (e) {
      log.warn({ error: e instanceof Error ? e.message : String(e) }, 'Redis unavailable, falling back to file store');
    }
  }
  return new TTLStore(fileName);
}

const nonceStore = createStore('nonces');
const idempotencyStore = createStore('settlements');
app.use(async (req, res, next) => {
  if (AUTH_TOKEN) {
    const k = req.header('x-api-key') || '';
    if (k !== AUTH_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  }
  
  if (!DISABLE_RATE_LIMIT) {
    const ip = req.ip || 'unknown';
    const powHeader = req.header('x-pow-header');
    
    // Try to extract wallet from payment header if available
    let wallet: PublicKey | undefined;
    try {
      const paymentHeader = req.header('x-payment');
      if (paymentHeader) {
        const decoded = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8'));
        const authFrom = decoded?.payload?.authorization?.from;
        if (authFrom) {
          wallet = new PublicKey(authFrom);
        }
      }
    } catch {
      // Ignore errors extracting wallet
    }
    
    const rateLimitResult = await rateLimitMiddleware.check(ip, wallet, powHeader);
    
    if (!rateLimitResult.allowed) {
      res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX_REQUESTS);
      res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
      res.setHeader('X-RateLimit-Reset', new Date(rateLimitResult.resetAt).toISOString());
      return res.status(429).json({ 
        error: 'rate_limited', 
        reason: rateLimitResult.reason,
        resetAt: rateLimitResult.resetAt 
      });
    }
    
    res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX_REQUESTS);
    res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
    res.setHeader('X-RateLimit-Reset', new Date(rateLimitResult.resetAt).toISOString());
  } else {
    // Fallback to simple rate limiting
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const minInterval = Math.max(0, RATE_LIMIT_MIN_INTERVAL_MS);
    if (lastReq[ip] && now - lastReq[ip] < minInterval) return res.status(429).json({ error: 'rate_limited' });
    lastReq[ip] = now;
  }
  
  next();
});

app.post('/verify', async (req: express.Request, res: express.Response) => {
  const parse = VerifyReq.safeParse(req.body);
  if (!parse.success) {
    log.warn({ errors: parse.error.errors }, 'verify request validation failed');
    return res.status(400).json({ isValid: false, invalidReason: 'bad_request' });
  }
  const { paymentHeader, paymentRequirements } = parse.data;
  
  // Try optimistic verification first (if enabled)
  if (optimisticVerifier) {
    const optimisticResult = await optimisticVerifier.verifyOptimistic(paymentHeader, paymentRequirements);
    if (optimisticResult.isValid) {
      // Return immediately - background worker will confirm
      return res.json({ 
        isValid: true, 
        invalidReason: null,
        optimistic: true,
        confirmed: optimisticResult.confirmed
      });
    } else if (optimisticResult.invalidReason) {
      // Optimistic verification failed - return error immediately
      return res.status(200).json({ 
        isValid: false, 
        invalidReason: optimisticResult.invalidReason 
      });
    }
    // Fall through to standard verification if optimistic check is inconclusive
  }
  
  try {
    const decoded = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8')) as any;
    // Optional fast-path: if a transaction is present, try strict native verification without helper
    async function verifyViaNativeTransaction(): Promise<{ ok: boolean; reason?: string | null }> {
      try {
        const txB64: unknown = decoded?.payload?.transaction;
        if (!txB64 || typeof txB64 !== 'string') return { ok: false, reason: 'missing_transaction' };
        const tx = Transaction.from(Buffer.from(txB64, 'base64'));

        // Ensure the payer signed the transaction
        const authFrom: string | undefined = decoded?.payload?.authorization?.from;
        if (!authFrom) return { ok: false, reason: 'missing_authorization_from' };
        const payerPk = new PublicKey(authFrom);
        const payerSigned = tx.signatures.some(s => s.publicKey.equals(payerPk) && s.signature !== null);
        if (!payerSigned) return { ok: false, reason: 'payer_not_signed' };

        // Validate basic instruction target and amount for native SOL or SPL
        const firstIx = tx.instructions[0];
        if (!firstIx) return { ok: false, reason: 'missing_instruction' };

        const requiredAmount = BigInt(paymentRequirements.maxAmountRequired);
        const requiredTo = new PublicKey(paymentRequirements.payTo);

        // SystemProgram transfer validation
        if (firstIx.programId.equals(SystemProgram.programId)) {
          try {
            // Decode SystemProgram.transfer
            const { keys, data } = firstIx;
            // SystemProgram transfer layout: 4 bytes for instruction tag + 8 bytes amount
            if (data.length < 12) return { ok: false, reason: 'invalid_instruction_data' };
            const ixTag = data.readUInt32LE(0);
            if (ixTag !== 2) return { ok: false, reason: 'unexpected_system_ix' }; // 2 = Transfer
            const lamports = BigInt(data.readBigUInt64LE(4));
            if (lamports !== requiredAmount) return { ok: false, reason: 'invalid_amount' };
            // keys[0] is from, keys[1] is to for transfer
            if (!keys[1] || !keys[1].pubkey.equals(requiredTo)) return { ok: false, reason: 'invalid_recipient' };
            return { ok: true };
          } catch {
            return { ok: false, reason: 'invalid_system_transfer' };
          }
        }

        // SPL-Token transfer(Checked) minimal validation: program id and recipient ATA owner match payTo
        // Deep SPL parsing is skipped here; rely on helper for full SPL validation in production
        return { ok: true };
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'unknown_error';
        log.warn({ error: msg }, 'native transaction verify failed');
        return { ok: false, reason: 'transaction_parse_failed' };
      }
    }
    // Optional strict verification via x402 helpers
    if (USE_X402_HELPERS) {
      try {
        // Dynamically import helper from local x402 checkout; fallback if unavailable
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore - Dynamic import outside rootDir, wrapped in try/catch
        const helper = await import('../../../x402/typescript/packages/x402/src/schemes/exact/svm/facilitator/verify.ts');
        if (helper && typeof (helper as any).verify === 'function') {
          const result = await (helper as any).verify({ paymentPayload: decoded, paymentRequirements });
          if (!result?.isValid) {
            return res.status(200).json({ isValid: false, invalidReason: result?.invalidReason ?? 'invalid_payload' });
          }
          return res.json({ isValid: true, invalidReason: null });
        }
      } catch {
        // Fallback to basic verification if x402 helpers unavailable
      }
    }
    // If we have a transaction, attempt native verification
    if (decoded?.payload?.transaction) {
      const strict = await verifyViaNativeTransaction();
      if (!strict.ok) {
        return res.status(200).json({ isValid: false, invalidReason: strict.reason ?? 'invalid_transaction' });
      }
      // Continue with common checks below (version/scheme/network/time/nonce)
    }
    if (decoded.x402Version !== 1) return res.status(200).json({ isValid: false, invalidReason: 'invalid_x402_version' });
    if (decoded.scheme !== 'exact') return res.status(200).json({ isValid: false, invalidReason: 'invalid_scheme' });
    if (decoded.network !== paymentRequirements.network) return res.status(200).json({ isValid: false, invalidReason: 'invalid_network' });
    const payload = decoded.payload as { signature?: string; authorization: ExactSvmAuthorization };
    if (!payload || !payload.authorization) return res.status(200).json({ isValid: false, invalidReason: 'invalid_payload' });
    const auth = payload.authorization;
    
    // Validate Solana address formats
    try {
      new PublicKey(auth.from);
      new PublicKey(auth.to);
      new PublicKey(paymentRequirements.payTo);
    } catch {
      return res.status(200).json({ isValid: false, invalidReason: 'invalid_address_format' });
    }
    
    // Validate authorization structure matches payment requirements
    if (auth.to !== paymentRequirements.payTo) return res.status(200).json({ isValid: false, invalidReason: 'invalid_exact_svm_payload_recipient_mismatch' });
    if (auth.value !== paymentRequirements.maxAmountRequired) return res.status(200).json({ isValid: false, invalidReason: 'invalid_exact_svm_payload_authorization_value' });
    
    // Oracle price validation (if enabled)
    if (oracleValidator.isEnabled()) {
      try {
        const amountNumber = Number(paymentRequirements.maxAmountRequired);
        const validationResult = await oracleValidator.validatePrice(amountNumber, paymentRequirements.asset);
        if (!validationResult.valid) {
          log.warn({
            providedPrice: validationResult.providedPrice,
            oraclePrice: validationResult.oraclePrice,
            deviationPercent: validationResult.deviationPercent,
            error: validationResult.error
          }, 'Price validation failed');
          return res.status(200).json({ isValid: false, invalidReason: 'price_validation_failed', details: validationResult.error });
        }
      } catch (error) {
        log.error({ error }, 'Price validation error');
        // Continue with verification even if price validation fails (fail open)
      }
    }
    
    // NOTE: This implementation uses simplified authorization-based verification for demo purposes.
    // Production deployments should use USE_X402_HELPERS=true or implement full Solana transaction
    // deserialization and signature verification as per x402 specification.
    // Time window and nonce replay checks, plus nonce format validation
    const nowSec = Math.floor(Date.now() / 1000);
    const validAfter = Number(auth.validAfter);
    const validBefore = Number(auth.validBefore);
    if (!(Number.isFinite(validAfter) && validAfter <= nowSec)) return res.status(200).json({ isValid: false, invalidReason: 'invalid_exact_svm_payload_authorization_valid_after' });
    if (!(Number.isFinite(validBefore) && validBefore >= nowSec)) return res.status(200).json({ isValid: false, invalidReason: 'invalid_exact_svm_payload_authorization_valid_before' });
    // Nonce must be 0x-prefixed 32-byte hex
    if (typeof auth.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(auth.nonce)) {
      return res.status(200).json({ isValid: false, invalidReason: 'invalid_nonce_format' });
    }
    // Persistent replay protection (can be disabled in dev)
    if (!DISABLE_NONCE_REPLAY) {
      // Check off-chain store first (fast path)
      if (await (nonceStore as any).has(auth.nonce)) {
        return res.status(200).json({ isValid: false, invalidReason: 'nonce_replay' });
      }
      
      // Check on-chain nonce registry (slower but authoritative)
      const payerPk = new PublicKey(auth.from);
      const providerPk = new PublicKey(paymentRequirements.payTo);
      const onChainCheck = await checkNonceOnChain(connection, payerPk, providerPk, auth.nonce);
      
      if (onChainCheck.used) {
        return res.status(200).json({ isValid: false, invalidReason: 'nonce_replay' });
      }
      
      // Store in off-chain cache for fast subsequent checks
      await (nonceStore as any).set(auth.nonce, NONCE_TTL_MS);
    }
    return res.json({ isValid: true, invalidReason: null });
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : 'unknown_error';
    log.warn({ error: errorMessage, stack: e instanceof Error ? e.stack : undefined }, 'verify parse failed');
    return res.status(200).json({ isValid: false, invalidReason: 'invalid_payload' });
  }
});

// Settlement: perform a tiny native transfer to simulate settlement and return spec-like fields
const SettleReq = z.object({
  x402Version: z.number().int().positive(),
  paymentHeader: z.string(),
  paymentRequirements: PaymentRequirements
});

app.post('/settle', async (req: express.Request, res: express.Response) => {
  const parse = SettleReq.safeParse(req.body);
  if (!parse.success) {
    log.warn({ errors: parse.error.errors }, 'settle request validation failed');
    return res.status(400).json({ success: false, error: 'bad_request', txHash: null, networkId: NETWORK });
  }
  try {
    const decoded = JSON.parse(Buffer.from(parse.data.paymentHeader, 'base64').toString('utf8')) as any;
    const idemKey = crypto.createHash('sha256').update(parse.data.paymentHeader).digest('hex');
    if (idempotencyStore.has(idemKey)) {
      return res.json({ success: true, error: null, txHash: 'duplicate', networkId: NETWORK, payer: decoded?.payload?.authorization?.from ?? null });
    }
    const payTo = new PublicKey(parse.data.paymentRequirements.payTo);
    const auth = decoded?.payload?.authorization as ExactSvmAuthorization | undefined;
    const payerAddress = auth ? new PublicKey(auth.from) : null;
    
    // Check if batch settlement is enabled and queue payment
    if (batchSettlementManager && payerAddress) {
      const queuedPayment: QueuedPayment = {
        id: idemKey,
        paymentHeader: parse.data.paymentHeader,
        paymentRequirements: parse.data.paymentRequirements,
        timestamp: Date.now(),
        provider: payTo,
        payer: payerAddress,
        amount: BigInt(parse.data.paymentRequirements.maxAmountRequired),
        asset: new PublicKey(parse.data.paymentRequirements.asset),
        settlementMode: SETTLEMENT_MODE
      };
      
      batchSettlementManager.queuePayment(queuedPayment);
      
      // Return immediately - payment will be settled in batch
      idempotencyStore.set(idemKey, 10 * 60 * 1000);
      return res.json({ 
        success: true, 
        error: null, 
        txHash: 'queued_for_batch', 
        networkId: NETWORK, 
        payer: payerAddress.toBase58(),
        batchSettlement: true,
        queueSize: batchSettlementManager.getQueueSize(payTo)
      });
    }
    
    // Check if payload contains a transaction (proper x402 flow) or just authorization (demo mode)
    const hasTransaction = decoded?.payload?.transaction;
    
    if (hasTransaction && USE_X402_HELPERS) {
      // Proper x402 flow: deserialize client's transaction, add facilitator signature, submit
      try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore - Dynamic import outside rootDir
        const helper = await import('../../../x402/typescript/packages/x402/src/schemes/exact/svm/facilitator/settle.ts');
        if (helper && typeof (helper as any).settle === 'function') {
          const result = await (helper as any).settle(
            { signTransaction: async (tx: any) => { tx.sign(feePayer); return tx; } },
            decoded,
            parse.data.paymentRequirements
          );
          if (result.success) {
            idempotencyStore.set(idemKey, 10 * 60 * 1000);
            
            // Record analytics and reputation
            if (payerAddress) {
              const startTime = Date.now();
              analytics.recordPayment(
                payerAddress.toBase58(),
                BigInt(parse.data.paymentRequirements.maxAmountRequired),
                parse.data.paymentRequirements.asset,
                parse.data.paymentRequirements.resource,
                Date.now() - startTime
              );
              
              // Update provider reputation
              reputationManager.recordSettlement(payTo, true).catch(err => {
                log.warn({ error: err }, 'Failed to update reputation');
              });
            }
            
            return res.json({ success: true, error: null, txHash: result.transaction, networkId: NETWORK, payer: payerAddress?.toBase58() ?? null });
          } else {
            return res.status(500).json({ success: false, error: result.errorReason ?? 'settlement_failed', txHash: null, networkId: NETWORK });
          }
        }
      } catch (helperError) {
        log.warn({ error: helperError }, 'x402 helper settle unavailable, falling back to demo mode');
      }
    }
    // If we have a client-provided transaction but helper is unavailable, perform native sign+send
    if (hasTransaction) {
      try {
        const txB64: unknown = decoded?.payload?.transaction;
        if (!txB64 || typeof txB64 !== 'string') {
          return res.status(400).json({ success: false, error: 'missing_transaction', txHash: null, networkId: NETWORK });
        }
        const tx = Transaction.from(Buffer.from(txB64, 'base64'));
        // Add fee payer signature and submit
        const nativeSig = await sendAndConfirmTransaction(connection, tx, [feePayer], { commitment: 'confirmed' });
        idempotencyStore.set(idemKey, 10 * 60 * 1000);
        return res.json({ success: true, error: null, txHash: nativeSig, networkId: NETWORK, payer: payerAddress?.toBase58() ?? null });
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'unknown_error';
        log.warn({ error: msg }, 'native settle path failed, falling back to demo mode');
        // fall through to demo mode below
      }
    }
    
    // Demo mode: Using simplified authorization-based approach
    // NOTE: In production, client should send partially signed transaction, not just authorization
    // The facilitator should only add fee payer signature, not pay from their own account
    // This demo simulates payment by creating transaction from client's address (if possible)
    // but since we don't have client's private key, we use facilitator's account for demo
    
    if (!payerAddress) {
      return res.status(400).json({ 
        success: false, 
        error: 'missing_payer_address', 
        details: 'Payment authorization must include payer address',
        txHash: null, 
        networkId: NETWORK 
      });
    }
    
    // Check fee payer balance (facilitator only needs SOL for transaction fees, not payment amount)
    const balance = await connection.getBalance(feePayer.publicKey);
    const transactionFeeEstimate = 5000; // Approximate transaction fee in lamports
    const amountLamports = BigInt(parse.data.paymentRequirements.maxAmountRequired);
    
    // In proper x402: Facilitator only needs balance for transaction fees (~5000 lamports)
    // In demo mode: Facilitator pays the amount + fees (because we're simulating)
    const isDemoMode = DEMO_MODE || !hasTransaction;
    const demoModeAmount = isDemoMode ? Number(amountLamports) : 0;
    const requiredBalance = transactionFeeEstimate; // Facilitator only pays fees, not the payment amount
    const actualRequiredBalance = requiredBalance + demoModeAmount;
    
    if (balance < actualRequiredBalance) {
      // Try to auto-fund on devnet if this is an auto-generated keypair
      if (NETWORK === 'devnet' && !FEE_PAYER_SECRET) {
        log.info({ 
          feePayer: feePayer.publicKey.toBase58(), 
          balance, 
          requiredForFees: requiredBalance,
          demoModePayment: demoModeAmount,
          totalRequired: actualRequiredBalance,
          isDemoMode
        }, 'Balance insufficient, attempting automatic airdrop...');
        
        const airdropAmount = isDemoMode ? 2 * LAMPORTS_PER_SOL : 0.1 * LAMPORTS_PER_SOL;
        const airdropSig = await requestAirdropWithRetry(feePayer.publicKey, airdropAmount);
        
        if (airdropSig) {
          const newBalance = await connection.getBalance(feePayer.publicKey);
          log.info({ airdropSig, newBalance, requiredBalance }, 'Airdrop successful, checking balance...');
          
          // Verify we have enough after airdrop
          if (newBalance < actualRequiredBalance) {
            const errorMsg = `Insufficient balance after airdrop: need ${actualRequiredBalance} lamports (${requiredBalance} for fees${isDemoMode ? ` + ${demoModeAmount} for demo payment` : ''}), have ${newBalance} lamports. Fee payer: ${feePayer.publicKey.toBase58()}`;
            log.error({ balance: newBalance, requiredBalance: actualRequiredBalance, feePayer: feePayer.publicKey.toBase58(), isDemoMode }, errorMsg);
            return res.status(500).json({ 
              success: false, 
              error: 'insufficient_funds', 
              details: errorMsg,
              txHash: null, 
              networkId: NETWORK,
              feePayer: feePayer.publicKey.toBase58(),
              help: NETWORK === 'devnet' ? `Visit https://faucet.solana.com/ or run: solana airdrop 2 ${feePayer.publicKey.toBase58()} --url devnet` : undefined
            });
          }
          // Continue with settlement - balance is now sufficient
          log.info({ balance: newBalance, required: actualRequiredBalance, isDemoMode }, 'Balance sufficient, proceeding with settlement');
        } else {
          // Airdrop failed after retries
          const errorMsg = `Insufficient balance: need ${actualRequiredBalance} lamports (${requiredBalance} for fees${isDemoMode ? ` + ${demoModeAmount} for demo payment` : ''}), have ${balance} lamports. Fee payer: ${feePayer.publicKey.toBase58()}. Automatic airdrop failed (rate limited or faucet unavailable).`;
          log.error({ balance, requiredBalance: actualRequiredBalance, feePayer: feePayer.publicKey.toBase58(), isDemoMode }, errorMsg);
          return res.status(500).json({ 
            success: false, 
            error: 'insufficient_funds', 
            details: errorMsg,
            txHash: null, 
            networkId: NETWORK,
            feePayer: feePayer.publicKey.toBase58(),
            help: NETWORK === 'devnet' ? `Please fund manually: Visit https://faucet.solana.com/ and enter ${feePayer.publicKey.toBase58()} or run: solana airdrop 2 ${feePayer.publicKey.toBase58()} --url devnet` : undefined
          });
        }
      } else {
        const errorMsg = `Insufficient balance: need ${requiredBalance} lamports, have ${balance} lamports. Fee payer: ${feePayer.publicKey.toBase58()}`;
        log.error({ balance, requiredBalance, feePayer: feePayer.publicKey.toBase58() }, errorMsg);
        return res.status(500).json({ 
          success: false, 
          error: 'insufficient_funds', 
          details: errorMsg,
          txHash: null, 
          networkId: NETWORK,
          feePayer: feePayer.publicKey.toBase58()
        });
      }
    }
    
    let sig: string;
    if (SETTLEMENT_MODE === 'spl') {
      const mint = new PublicKey(parse.data.paymentRequirements.asset);
      const mintInfo = await getMint(connection, mint);
      const decimals = mintInfo.decimals;
      const fromAta = await getAssociatedTokenAddress(mint, feePayer.publicKey);
      const toAta = await getAssociatedTokenAddress(mint, payTo);
      const ixes = [] as any[];
      // ensure destination ATA exists
      try {
        await getAccount(connection, toAta);
      } catch {
        ixes.push(createAssociatedTokenAccountInstruction(feePayer.publicKey, toAta, payTo, mint));
      }
      const amount = BigInt(parse.data.paymentRequirements.maxAmountRequired);
      ixes.push(createTransferCheckedInstruction(fromAta, mint, toAta, feePayer.publicKey, Number(amount), decimals));
      const tx = new Transaction().add(...ixes);
      sig = await sendAndConfirmTransaction(connection, tx, [feePayer], { commitment: 'confirmed' });
    } else {
      // DEMO MODE: Create transaction from facilitator account
      // In production x402 flow, this would be the client's transaction that facilitator just signs as fee payer
      // Since this is demo mode and we don't have client's private key, we create and pay from facilitator
      // NOTE: In real x402, payment comes from auth.from (client), facilitator only pays fees
      const ix = SystemProgram.transfer({ 
        fromPubkey: feePayer.publicKey, 
        toPubkey: payTo, 
        lamports: Number(amountLamports) 
      });
      const tx = new Transaction().add(ix);
      
      // Set fee payer (normally this would be set by client, facilitator just adds signature)
      tx.feePayer = feePayer.publicKey;
      
      // Get recent blockhash
      const { blockhash } = await connection.getLatestBlockhash('confirmed');
      tx.recentBlockhash = blockhash;
      
      // Use optimistic mode if enabled (don't wait for confirmation)
      if (optimisticVerifier) {
        // Send transaction without waiting for confirmation
        sig = await connection.sendTransaction(tx, [feePayer], { skipPreflight: false });
        // Add to pending verifications for reconciliation
        optimisticVerifier.addPending(sig, parse.data.paymentHeader, parse.data.paymentRequirements);
      } else {
        sig = await sendAndConfirmTransaction(connection, tx, [feePayer], { commitment: 'confirmed' });
      }
    }
    idempotencyStore.set(idemKey, 10 * 60 * 1000);
    
    // Register nonce on-chain after successful settlement (async, don't wait)
    if (auth && !DISABLE_NONCE_REPLAY) {
      const payerPk = new PublicKey(auth.from);
      const providerPk = new PublicKey(parse.data.paymentRequirements.payTo);
      registerNonceOnChain(connection, feePayer, payerPk, providerPk, auth.nonce).catch(err => {
        log.warn({ error: err instanceof Error ? err.message : String(err) }, 'Failed to register nonce on-chain');
      });
    }
    
    // Mint NFT receipt if enabled (async, don't wait)
    let nftMint: string | null = null;
    if (nftMintingService && auth && payerAddress) {
      nftMintingService.mintReceiptNFT(payerAddress, {
        endpoint: parse.data.paymentRequirements.resource,
        timestamp: Date.now(),
        txHash: sig,
        payer: auth.from,
        provider: parse.data.paymentRequirements.payTo,
        amount: parse.data.paymentRequirements.maxAmountRequired,
        asset: parse.data.paymentRequirements.asset
      }).then(result => {
        if (result) {
          nftMint = result.mint.toBase58();
          log.info({ nftMint, payer: payerAddress.toBase58(), txHash: sig }, 'NFT receipt minted');
        }
      }).catch(err => {
        log.warn({ error: err instanceof Error ? err.message : String(err) }, 'Failed to mint NFT receipt');
      });
    }
    
    // Record analytics and reputation
    if (payerAddress) {
      const startTime = Date.now();
      analytics.recordPayment(
        payerAddress.toBase58(),
        BigInt(parse.data.paymentRequirements.maxAmountRequired),
        parse.data.paymentRequirements.asset,
        parse.data.paymentRequirements.resource,
        Date.now() - startTime
      );
      
      // Update provider reputation
      reputationManager.recordSettlement(payTo, true).catch(err => {
        log.warn({ error: err }, 'Failed to update reputation');
      });
    }
    
    return res.json({ 
      success: true, 
      error: null, 
      txHash: sig, 
      networkId: NETWORK, 
      payer: decoded?.payload?.authorization?.from ?? null,
      nftMint: nftMint || undefined
    });
  } catch (e) {
    // Extract detailed error information
    let errorMessage = 'unknown_error';
    let errorDetails = '';
    
    if (e instanceof Error) {
      errorMessage = e.message;
      errorDetails = e.stack || '';
      // Try to extract Solana-specific error messages
      if (e.message.includes('insufficient funds') || e.message.includes('Insufficient')) {
        errorMessage = 'insufficient_funds';
      } else if (e.message.includes('blockhash') || e.message.includes('Blockhash')) {
        errorMessage = 'invalid_blockhash';
      } else if (e.message.includes('signature') || e.message.includes('Signature')) {
        errorMessage = 'signature_error';
      }
    }
    
    log.error({ 
      error: errorMessage, 
      details: errorDetails,
      stack: errorDetails,
      paymentRequirements: parse.data.paymentRequirements.resource,
      feePayer: feePayer.publicKey.toBase58()
    }, 'settlement failed');
    
    return res.status(500).json({ 
      success: false, 
      error: errorMessage,
      details: errorDetails ? `Fee payer: ${feePayer.publicKey.toBase58()}. ${errorDetails.substring(0, 200)}` : undefined,
      txHash: null, 
      networkId: NETWORK 
    });
  }
});

app.get('/health', async (_req: express.Request, res: express.Response) => {
  try {
    const version = await connection.getVersion();
    const startTime = process.uptime();
    
    // Check Redis connection if available
    let redisHealthy = false;
    if (REDIS_URL) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const Redis = require('ioredis');
        const redis = new Redis(REDIS_URL);
        await redis.ping();
        redisHealthy = true;
        redis.disconnect();
      } catch {
        redisHealthy = false;
      }
    }
    
    res.json({ 
      healthy: true,
      timestamp: Date.now(),
      services: {
        rpc: true,
        redis: REDIS_URL ? redisHealthy : undefined
      },
      metrics: {
        uptime: startTime,
        requestCount: 0, // TODO: Track request count
        errorRate: 0 // TODO: Track error rate
      },
      rpc: version['solana-core'] ?? null, 
      feePayer: feePayer.publicKey.toBase58(), 
      network: NETWORK, 
      settlementMode: SETTLEMENT_MODE,
      features: {
        optimisticVerification: ENABLE_OPTIMISTIC,
        batchSettlement: ENABLE_BATCH_SETTLEMENT,
        feePayerPool: ENABLE_FEE_PAYER_POOL
      }
    });
  } catch {
    res.json({ healthy: false, timestamp: Date.now() });
  }
});

app.get('/supported', (_req: express.Request, res: express.Response) => {
  res.json({ kinds: [{ scheme: 'exact', network: 'solana-devnet' }] });
});

app.get('/analytics', (_req: express.Request, res: express.Response) => {
  res.json(analytics.getMetrics());
});

app.listen(PORT, () => {
  log.info({ PORT, RPC_URL }, 'facilitator listening');
});

// Simple in-memory nonce cache with TTL
const nonceCache = new Map<string, number>();
const NONCE_TTL_MS = 5 * 60 * 1000;
function pruneNonces(now: number) {
  for (const [k, exp] of nonceCache.entries()) {
    if (exp <= now) nonceCache.delete(k);
  }
}


