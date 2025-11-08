# MicroAPI Hub - Production Deployment Guide

This guide walks you through deploying MicroAPI Hub to production on Vercel (frontend) and persistent hosting for backend services.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Phase 1: Frontend Deployment (Vercel)](#phase-1-frontend-deployment-vercel)
- [Phase 2: Backend Deployment](#phase-2-backend-deployment)
- [Phase 3: Environment Configuration](#phase-3-environment-configuration)
- [Phase 4: Security Hardening](#phase-4-security-hardening)
- [Phase 5: Monitoring Setup](#phase-5-monitoring-setup)
- [Phase 6: Post-Deployment Validation](#phase-6-post-deployment-validation)
- [Troubleshooting](#troubleshooting)
- [Rollback Procedures](#rollback-procedures)

## Prerequisites

- GitHub repository with code
- Vercel account (for frontend)
- Render/Fly.io/DigitalOcean account (for backend)
- Managed Postgres database (Supabase/Neon/Render)
- Managed Redis instance (Upstash/Redis Labs)
- AWS/GCP account (for KMS, if using HSM)
- Solana wallet with funds (for fee payer)
- Domain name (optional, for custom domains)

## Architecture Overview

```
┌─────────────────┐
│  Next.js App    │  → Vercel (Serverless)
│  (Frontend)     │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│  Provider API   │  → Render/Fly (Persistent)
│  (x402 Guard)   │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  Facilitator    │  → Render/Fly (Persistent)
│  (Verify/Settle)│
└────────┬────────┘
         │ RPC
         ▼
┌─────────────────┐
│  Solana Network │  → Mainnet/Devnet
│  (Blockchain)   │
└─────────────────┘
```

## Phase 1: Frontend Deployment (Vercel)

### Step 1.1: Connect Repository to Vercel

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "Add New Project"
3. Import your GitHub repository
4. Select the repository containing MicroAPI Hub

### Step 1.2: Configure Build Settings

- **Framework Preset**: Next.js
- **Root Directory**: `clients/web`
- **Build Command**: `npm run build` (default)
- **Output Directory**: `.next` (default)
- **Install Command**: `npm ci`

### Step 1.3: Set Environment Variables

In Vercel Project Settings → Environment Variables, add:

```bash
NEXT_PUBLIC_PROVIDER_DISCOVERY_URL=https://api.yourdomain.com/.well-known/x402
NEXT_PUBLIC_FACILITATOR_URL=https://facilitator.yourdomain.com
NEXT_PUBLIC_NETWORK=mainnet-beta
NEXT_PUBLIC_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
NEXT_PUBLIC_SOLANA_EXPLORER=https://explorer.solana.com
```

**Important**: 
- Use `NEXT_PUBLIC_` prefix for variables exposed to the browser
- Set these for Production, Preview, and Development environments
- Update URLs to match your actual backend services

### Step 1.4: Deploy

1. Push to `main` branch to trigger automatic deployment
2. Or click "Deploy" in Vercel dashboard
3. Wait for build to complete
4. Access your app at `https://your-project.vercel.app`

### Step 1.5: Custom Domain (Optional)

1. Go to Project Settings → Domains
2. Add your custom domain
3. Configure DNS records as instructed
4. SSL certificate is automatically provisioned

## Phase 2: Backend Deployment

### Option A: Render (Recommended for Simplicity)

#### Step 2.1: Deploy Facilitator Service

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `microapi-facilitator`
   - **Region**: Choose closest to your users
   - **Branch**: `main`
   - **Root Directory**: `services/facilitator`
   - **Build Command**: `npm ci && npm run build`
   - **Start Command**: `npm start`
   - **Environment**: `Docker` (or `Node` if using Node directly)

5. Add environment variables (see Phase 3)

6. Set up Health Check:
   - **Health Check Path**: `/health`

7. Deploy

#### Step 2.2: Deploy Provider API

1. Repeat steps above with:
   - **Name**: `microapi-provider-api`
   - **Root Directory**: `services/provider-api`

### Option B: Fly.io (Recommended for Global Distribution)

#### Step 2.1: Install Fly CLI

```bash
curl -L https://fly.io/install.sh | sh
```

#### Step 2.2: Deploy Facilitator

```bash
cd services/facilitator
flyctl launch --name microapi-facilitator --region ord
flyctl secrets set FEE_PAYER_SECRET=... NETWORK=mainnet-beta ...
flyctl deploy
```

#### Step 2.3: Deploy Provider API

```bash
cd services/provider-api
flyctl launch --name microapi-provider-api --region ord
flyctl secrets set PAY_TO_PUBKEY=... FACILITATOR_URL=...
flyctl deploy
```

### Option C: Docker + Any Platform

If using Docker directly:

```bash
# Build images
docker build -t microapi-facilitator services/facilitator
docker build -t microapi-provider-api services/provider-api

# Push to registry
docker tag microapi-facilitator ghcr.io/your-org/microapi-facilitator:latest
docker push ghcr.io/your-org/microapi-facilitator:latest

# Deploy to your platform (ECS, Kubernetes, etc.)
```

## Phase 3: Environment Configuration

### 3.1 Facilitator Service Variables

**Required:**
```bash
PORT=8787
NETWORK=mainnet-beta
RPC_URL=https://api.mainnet-beta.solana.com
FEE_PAYER_SECRET=<base58-secret>  # Or use KMS (see Security section)
SETTLEMENT_MODE=native
DEMO_MODE=false
```

**Optional but Recommended:**
```bash
REDIS_URL=redis://:password@redis-host:6379
DB_URL=postgres://user:pass@host:5432/microapi
KEY_MANAGEMENT_TYPE=hsm
HSM_PROVIDER=aws_kms
HSM_ENDPOINT=https://kms.region.amazonaws.com
HSM_API_KEY=...
ORACLE_PROVIDER=pyth
ORACLE_PRICE_FEED_ID=...
SENTRY_DSN=https://...
```

### 3.2 Provider API Variables

**Required:**
```bash
PORT=8080
PAY_TO_PUBKEY=<provider-pubkey>
USDC_MINT=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
FACILITATOR_URL=https://facilitator.yourdomain.com
```

**Optional:**
```bash
ENABLE_RESPONSE_SIGNING=true
PROVIDER_SECRET_KEY=<base58-secret>
```

### 3.3 Database Setup

1. Create managed Postgres instance (Supabase/Neon/Render)
2. Get connection string
3. Run migrations (if using Prisma/TypeORM):
   ```bash
   npx prisma migrate deploy
   ```
4. Set `DB_URL` in facilitator environment

### 3.4 Redis Setup

1. Create managed Redis instance (Upstash/Redis Labs)
2. Get connection string
3. Set `REDIS_URL` in facilitator environment

## Phase 4: Security Hardening

### 4.1 Key Management (Critical)

**Never store private keys in environment variables in production!**

#### Option A: AWS KMS

1. Create KMS key in AWS Console
2. Configure IAM role for your service
3. Use KMS adapter (see `shared/signers/kms-adapter.ts`)
4. Set environment variables:
   ```bash
   KEY_MANAGEMENT_TYPE=hsm
   HSM_PROVIDER=aws_kms
   HSM_ENDPOINT=https://kms.region.amazonaws.com
   HSM_API_KEY=<aws-access-key>
   ```

#### Option B: GCP KMS

Similar process with GCP Cloud KMS.

#### Option C: HashiCorp Vault

1. Deploy Vault instance
2. Configure authentication
3. Store keys in Vault
4. Use Vault API to retrieve keys at runtime

### 4.2 CORS Configuration

Update facilitator and provider API to restrict CORS:

```typescript
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  credentials: true
}));
```

### 4.3 Rate Limiting

Already configured in facilitator. Ensure `REDIS_URL` is set for production.

### 4.4 Security Headers

Already configured in `vercel.json` and `next.config.cjs`. Verify they're applied.

## Phase 5: Monitoring Setup

### 5.1 Sentry (Error Tracking)

1. Create Sentry project
2. Get DSN
3. Set `SENTRY_DSN` in environment variables
4. Install Sentry SDK (if not already):
   ```bash
   npm install @sentry/nextjs
   ```

### 5.2 Logging

- Structured logging with Pino is already configured
- Set up log aggregation (Logflare, Datadog, etc.)
- Configure log drains in your hosting platform

### 5.3 Metrics

- Add Prometheus metrics endpoint (optional)
- Set up Grafana dashboards
- Configure alerts for:
  - High error rates
  - Slow settlement times
  - Low fee payer balance

### 5.4 Uptime Monitoring

- Use UptimeRobot, Pingdom, or similar
- Monitor:
  - Frontend: `https://yourdomain.com`
  - Facilitator: `https://facilitator.yourdomain.com/health`
  - Provider API: `https://api.yourdomain.com/health`

## Phase 6: Post-Deployment Validation

### 6.1 Smoke Tests

```bash
# Test frontend
curl https://yourdomain.com

# Test facilitator health
curl https://facilitator.yourdomain.com/health

# Test provider discovery
curl https://api.yourdomain.com/.well-known/x402

# Test payment flow
# Use the web UI to make a test payment
```

### 6.2 Verify Environment Variables

- Check all `NEXT_PUBLIC_*` variables are set correctly
- Verify backend services can connect to database/Redis
- Confirm RPC URL is accessible

### 6.3 Test Payment Flow

1. Open web app
2. Connect wallet
3. Browse available APIs
4. Make a test payment
5. Verify transaction on Solana explorer
6. Check facilitator logs for settlement

## Troubleshooting

### Issue: Frontend can't connect to backend

**Solution:**
- Verify `NEXT_PUBLIC_FACILITATOR_URL` and `NEXT_PUBLIC_PROVIDER_DISCOVERY_URL` are correct
- Check CORS configuration on backend
- Verify backend services are running

### Issue: Facilitator returns "insufficient_funds"

**Solution:**
- Check fee payer balance on Solana
- Fund the account if needed
- Verify `FEE_PAYER_SECRET` is correct

### Issue: Payment verification fails

**Solution:**
- Check facilitator logs
- Verify nonce is not reused
- Check time window validity
- Verify signature is correct

### Issue: Build fails on Vercel

**Solution:**
- Check Node.js version (should be 18+)
- Verify all dependencies are in `package.json`
- Check build logs for specific errors
- Ensure `package-lock.json` is committed

## Rollback Procedures

### Frontend (Vercel)

1. Go to Vercel Dashboard → Deployments
2. Find previous successful deployment
3. Click "..." → "Promote to Production"

### Backend (Render)

1. Go to Render Dashboard → Service
2. Click "Manual Deploy"
3. Select previous commit
4. Deploy

### Backend (Fly.io)

```bash
flyctl releases list
flyctl releases rollback <release-id>
```

## Additional Resources

- [Vercel Documentation](https://vercel.com/docs)
- [Render Documentation](https://render.com/docs)
- [Fly.io Documentation](https://fly.io/docs)
- [Solana RPC Providers](https://docs.solana.com/cluster/rpc-endpoints)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)

## Support

For issues or questions:
- Open a GitHub issue
- Check logs in your hosting platform
- Review error tracking (Sentry)

---

**Last Updated**: 2025-01-08

