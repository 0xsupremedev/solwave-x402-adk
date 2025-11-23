# 🌊 SolWave - AI-Powered Payments for the Autonomous Web

<div align="center">

![SolWave](https://img.shields.io/badge/SolWave-x402-blue?style=for-the-badge&logo=solana)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-15.2.4-black?style=for-the-badge&logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=for-the-badge&logo=typescript)
![Solana](https://img.shields.io/badge/Solana-Web3-purple?style=for-the-badge&logo=solana)

**Experience real on-chain payments, autonomous agents, and decentralized commerce — all powered by Solana, x402, MCP tools, and the Google ADK.**

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Architecture](#-architecture) • [Contributing](#-contributing)

</div>

---
<img width="1888" height="1079" alt="image" src="https://github.com/user-attachments/assets/82361da9-f776-4b43-95e0-10848f6deff8" />


## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Commands & Usage](#-commands--usage)
- [API Reference](#-api-reference)
- [SDK Usage](#-sdk-usage)
- [Examples](#-examples)
- [Development](#-development)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**SolWave** is a complete platform for AI-powered payments on Solana using the x402 payment protocol, Google Agent Development Kit (ADK), and autonomous agents. The platform enables AI agents to request, verify, and execute cryptocurrency payments in real-time — facilitating true agent-to-agent commerce.

### Key Capabilities

- 🤖 **Autonomous Agents**: Build AI agents that can transact, charge, and verify payments automatically
- 💰 **x402 Protocol**: Machine-verifiable payment requests designed for AI ↔ AI commerce
- ⚡ **Solana Integration**: Fast, cheap transactions with USDC SPL token support
- 🔗 **Google ADK**: Full integration with Google's Agent Development Kit
- 📱 **Telegram Bot**: Deploy agents directly into Telegram conversations
- 🛠️ **Developer SDK**: JavaScript/TypeScript SDK for easy integration

---

## ✨ Features

### Core Features

- ✅ **Landing Page**: Complete marketing site with hero, features, live demo, and documentation
- ✅ **x402 Payment Protocol**: Invoice creation, payment requests, and verification
- ✅ **Solana Integration**: Transaction creation, signing, and on-chain verification
- ✅ **ADK Integration**: Client and merchant agent templates with chat UI
- ✅ **Authentication**: NextAuth.js with email/password and OAuth (Google/GitHub)
- ✅ **User Dashboards**: Profile, API keys, and wallet management
- ✅ **Merchant Dashboard**: Settings, invoices, and transaction management
- ✅ **Telegram Bot**: Webhook handler for Telegram integration
- ✅ **SDK**: JavaScript/TypeScript SDK for easy integration
- ✅ **Documentation**: Complete docs with quickstart guides
- ✅ **Observability**: Logging, metrics, and audit trails

### Advanced Features

- 🔐 **Security**: Noncustodial wallet signing, anti-replay protection, invoice expiry
- 📊 **Analytics**: Payment metrics, success rates, confirmation times
- 🔔 **Webhooks**: Real-time notifications for payment events
- 🎨 **Modern UI**: Glassmorphism design with Three.js particle effects
- 📱 **Responsive**: Mobile-first design with adaptive layouts
- 🌙 **Dark Theme**: Beautiful blue-themed dark mode

---

## 🛠️ Tech Stack

### Frontend

![Next.js](https://img.shields.io/badge/Next.js-15.2.4-000000?style=flat&logo=next.js&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat&logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.1.9-38B2AC?style=flat&logo=tailwind-css&logoColor=white)
![Three.js](https://img.shields.io/badge/Three.js-latest-000000?style=flat&logo=three.js&logoColor=white)
![Radix UI](https://img.shields.io/badge/Radix_UI-Primitives-161618?style=flat&logo=radix-ui&logoColor=white)

### Blockchain & Web3

![Solana](https://img.shields.io/badge/Solana-Web3.js-14F195?style=flat&logo=solana&logoColor=white)
![SPL Token](https://img.shields.io/badge/SPL_Token-0.4.14-14F195?style=flat&logo=solana&logoColor=white)
![Wallet Adapter](https://img.shields.io/badge/Wallet_Adapter-0.15.35-14F195?style=flat&logo=solana&logoColor=white)

### Backend

![Node.js](https://img.shields.io/badge/Node.js-Latest-339933?style=flat&logo=node.js&logoColor=white)
![Prisma](https://img.shields.io/badge/Prisma-6.19.0-2D3748?style=flat&logo=prisma&logoColor=white)
![NextAuth.js](https://img.shields.io/badge/NextAuth.js-4.24.13-000000?style=flat&logo=next.js&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat&logo=sqlite&logoColor=white)

### Tools & Libraries

![Zod](https://img.shields.io/badge/Zod-3.25.67-3E63DD?style=flat&logo=zod&logoColor=white)
![Zustand](https://img.shields.io/badge/Zustand-5.0.8-FF6B6B?style=flat)
![React Query](https://img.shields.io/badge/React_Query-5.90.10-FF4154?style=flat&logo=react-query&logoColor=white)
![Lucide Icons](https://img.shields.io/badge/Lucide_Icons-0.454.0-FF6B6B?style=flat)

### Development

![ESLint](https://img.shields.io/badge/ESLint-Latest-4B32C3?style=flat&logo=eslint&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat&logo=typescript&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-Latest-F69220?style=flat&logo=pnpm&logoColor=white)

---

## 🏗️ Architecture

```mermaid
graph TB
    subgraph "Frontend Layer"
        A[Next.js App] --> B[React Components]
        B --> C[Wallet Provider]
        B --> D[Chat UI]
        B --> E[Payment Flows]
    end

    subgraph "Agent Layer"
        F[Client Agent] --> G[ADK Client]
        H[Merchant Agent] --> G
        G --> I[x402 Tools]
        G --> J[Payment Tools]
    end

    subgraph "API Layer"
        K[Next.js API Routes] --> L[Invoice API]
        K --> M[Auth API]
        K --> N[MCP Router]
        K --> O[Telegram Webhook]
    end

    subgraph "Business Logic"
        L --> P[x402 Service]
        P --> Q[Invoice Manager]
        P --> R[Payment Verifier]
        N --> S[MCP Services]
        S --> T[Merchant Service]
        S --> U[Payment Service]
    end

    subgraph "Blockchain Layer"
        V[Solana RPC] --> W[Transaction Builder]
        W --> X[Wallet Signer]
        X --> Y[Solana Network]
        R --> Y
    end

    subgraph "Data Layer"
        Z[Prisma ORM] --> AA[(SQLite Database)]
        AA --> AB[Users]
        AA --> AC[Merchants]
        AA --> AD[Invoices]
        AA --> AE[Sessions]
    end

    subgraph "External Services"
        AF[Google ADK] --> G
        AG[Telegram Bot] --> O
        AH[Webhooks] --> T
    end

    A --> K
    F --> K
    H --> K
    C --> X
    E --> W
    K --> Z
    Q --> AA
    R --> V
    T --> AH
    O --> AG
    G --> AF

    style A fill:#0a1628,stroke:#3b82f6,stroke-width:2px
    style G fill:#14F195,stroke:#9945FF,stroke-width:2px
    style P fill:#FF6B6B,stroke:#4ECDC4,stroke-width:2px
    style Y fill:#9945FF,stroke:#14F195,stroke-width:2px
    style AA fill:#2D3748,stroke:#48BB78,stroke-width:2px
```

### Component Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant ClientAgent
    participant API
    participant MerchantAgent
    participant Solana
    participant Database

    User->>Frontend: Request Payment
    Frontend->>ClientAgent: Process Request
    ClientAgent->>API: Create Invoice
    API->>Database: Store Invoice
    API->>MerchantAgent: Notify Payment Request
    MerchantAgent->>API: Generate Payment Instructions
    API->>Frontend: Return Payment Request
    Frontend->>User: Show Payment UI
    User->>Frontend: Approve & Sign
    Frontend->>Solana: Submit Transaction
    Solana-->>Frontend: Transaction Signature
    Frontend->>API: Update Invoice Status
    API->>Database: Mark Invoice as Paid
    API->>MerchantAgent: Notify Payment Confirmed
    MerchantAgent->>API: Complete Service
    API-->>Frontend: Payment Confirmed
    Frontend-->>User: Show Confirmation
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ ([Download](https://nodejs.org/))
- **pnpm** ([Install](https://pnpm.io/installation))
- **Git** ([Download](https://git-scm.com/))
- **Solana CLI** (optional, for devnet testing)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/0xsupremedev/solwave-x402-adk.git
cd solwave-x402-adk
```

2. **Install dependencies**

```bash
pnpm install
```

3. **Set up environment variables**

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL="file:./prisma/dev.db"

# NextAuth
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-secret-key-change-in-production"

# Solana
SOLANA_CLUSTER="devnet"
SOLANA_RPC_URL="https://api.devnet.solana.com"

# Optional: OAuth providers
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""

# Optional: Telegram Bot
TELEGRAM_BOT_TOKEN=""
TELEGRAM_WEBHOOK_URL=""
```

4. **Set up the database**

```bash
# Generate Prisma client
pnpm prisma generate

# Run migrations
pnpm prisma migrate dev

# (Optional) Open Prisma Studio
pnpm prisma studio
```

5. **Start the development server**

```bash
pnpm dev
```

The application will be available at `http://localhost:3000`

---

## 📝 Commands & Usage

### Development Commands

```bash
# Start development server
pnpm dev

# Build for production
pnpm build

# Start production server
pnpm start

# Run linter
pnpm lint

# Type check
pnpm type-check
```

### Database Commands

```bash
# Generate Prisma client
pnpm prisma generate

# Create new migration
pnpm prisma migrate dev --name migration_name

# Reset database (⚠️ deletes all data)
pnpm prisma migrate reset

# Open Prisma Studio (database GUI)
pnpm prisma studio

# Format Prisma schema
pnpm prisma format

# Validate Prisma schema
pnpm prisma validate
```

### Testing Commands

```bash
# Run tests (if configured)
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage
pnpm test:coverage
```

### Build & Deployment

```bash
# Build for production
pnpm build

# Start production server
pnpm start

# Analyze bundle size
pnpm analyze
```

---

## 📚 API Reference

### Invoice Management

#### Create Invoice

```http
POST /api/v1/invoices
Content-Type: application/json

{
  "merchantId": "merchant-123",
  "amount": "1.0",
  "token": "USDC",
  "metadata": {
    "item": "Digital Product",
    "description": "Premium access"
  }
}
```

**Response:**

```json
{
  "id": "invoice-123",
  "merchantId": "merchant-123",
  "amount": "1.0",
  "token": "USDC",
  "status": "pending",
  "expiresAt": "2024-01-01T12:00:00Z",
  "nonce": "abc123...",
  "createdAt": "2024-01-01T11:00:00Z"
}
```

#### Get Invoice

```http
GET /api/v1/invoices/:id
```

#### List Invoices

```http
GET /api/v1/invoices?merchantId=merchant-123&status=pending&limit=10&offset=0
```

#### Update Invoice Status

```http
POST /api/v1/invoices/:id
Content-Type: application/json

{
  "txSignature": "5j7s8...",
  "status": "paid"
}
```

### Webhook Management

#### Register Webhook

```http
POST /api/v1/webhooks/register
Content-Type: application/json

{
  "merchantId": "merchant-123",
  "url": "https://example.com/webhook",
  "events": ["invoice.paid", "invoice.expired"]
}
```

### Agent Sessions

#### List Sessions

```http
GET /api/v1/agents/:id/sessions
```

#### Create Session

```http
POST /api/v1/agents/:id/sessions
Content-Type: application/json

{
  "traceEvents": [],
  "artifacts": [],
  "state": {}
}
```

### Authentication

#### Sign Up

```http
POST /api/auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password",
  "name": "John Doe"
}
```

#### NextAuth Endpoints

- `GET /api/auth/signin` - Sign in page
- `GET /api/auth/signout` - Sign out
- `GET /api/auth/callback/:provider` - OAuth callback
- `GET /api/auth/session` - Get current session
- `POST /api/auth/csrf` - Get CSRF token

---

## 💻 SDK Usage

### Installation

```bash
npm install @solwave/sdk
# or
pnpm add @solwave/sdk
```

### Basic Usage

```typescript
import { createSDK } from '@solwave/sdk';

const sdk = createSDK({
  apiUrl: 'http://localhost:3000',
  apiKey: 'your-api-key',
});

// Create invoice
const invoice = await sdk.createInvoice({
  merchantId: 'merchant-123',
  amount: '1.0',
  token: 'USDC',
});

// Watch invoice status
const unwatch = await sdk.watchInvoice(invoice.id, (status) => {
  console.log('Invoice status:', status);
});

// Stop watching
unwatch();
```

### ADK Agents

#### Client Agent

```typescript
import { ADKClient } from '@solwave/sdk';

const client = new ADKClient();
const buyerAgent = client.createClientAgent('buyer-agent-1', 'user-123');

const result = await buyerAgent.processPurchase(
  'merchant-123',
  '1.0',
  'USDC'
);
```

#### Merchant Agent

```typescript
const merchantAgent = client.createMerchantAgent(
  'merchant-agent-1',
  'merchant-123',
  'YourSolanaAddressHere'
);

const result = await merchantAgent.processPaymentRequest('1.0', 'USDC');
```

---

## 📖 Examples

### Example 1: Basic Payment Flow

```typescript
// 1. Create invoice
const invoice = await sdk.createInvoice({
  merchantId: 'merchant-123',
  amount: '1.0',
  token: 'USDC',
});

// 2. Build transaction
const transaction = await sdk.buildTransaction({
  invoiceId: invoice.id,
  payer: wallet.publicKey,
});

// 3. Sign transaction
const signedTx = await wallet.signTransaction(transaction);

// 4. Submit transaction
const signature = await sdk.submitTransaction(signedTx);

// 5. Confirm payment
const confirmation = await sdk.confirmPayment(invoice.id, signature);
```

### Example 2: Using ADK Agents

```typescript
// Client agent requests payment
const clientAgent = new ClientAgent({
  agentId: 'buyer-1',
  userId: 'user-123',
});

const paymentRequest = await clientAgent.requestPayment({
  merchantId: 'merchant-123',
  amount: '1.0',
  token: 'USDC',
});

// Merchant agent processes payment
const merchantAgent = new MerchantAgent({
  agentId: 'merchant-1',
  merchantId: 'merchant-123',
  receivingAddress: 'SolanaAddress...',
});

const invoice = await merchantAgent.createInvoice({
  amount: '1.0',
  token: 'USDC',
});
```

See the [`examples/`](./examples/) directory for more complete examples.

---

## 🔧 Development

### Project Structure

```
solwave-x402-adk/
├── app/                    # Next.js app directory
│   ├── api/               # API routes
│   │   ├── auth/          # Authentication endpoints
│   │   ├── mcp/           # MCP server endpoints
│   │   ├── telegram/      # Telegram webhook
│   │   └── v1/            # API v1 endpoints
│   ├── chat/              # Chat dashboard page
│   ├── dashboard/         # User dashboard
│   ├── docs/              # Documentation pages
│   ├── merchant/          # Merchant dashboard
│   └── page.tsx           # Landing page
├── components/            # React components
│   ├── chat/              # Chat UI components
│   ├── auth/              # Authentication components
│   ├── wallet/            # Wallet integration
│   ├── flows/             # Payment flow components
│   └── ui/                # UI components (shadcn)
├── lib/                   # Library code
│   ├── adk/               # ADK integration
│   ├── solana/            # Solana integration
│   ├── x402/              # x402 protocol
│   ├── auth/              # Authentication config
│   ├── db/                # Database client
│   ├── sdk/               # SDK implementation
│   └── observability/     # Logging and metrics
├── prisma/                # Prisma schema
├── examples/              # Example applications
│   ├── buyer-webflow/     # Buyer agent example
│   ├── merchant-agent/    # Merchant agent example
│   └── telegram-bot/      # Telegram bot example
└── public/                # Static assets
```

### Adding New Features

1. **Create feature branch**

```bash
git checkout -b feature/your-feature-name
```

2. **Make changes and test**

```bash
pnpm dev
# Test your changes
```

3. **Commit changes**

```bash
git add .
git commit -m "feat: add your feature"
```

4. **Push and create PR**

```bash
git push origin feature/your-feature-name
```

### Code Style

- Use TypeScript for all new code
- Follow ESLint rules
- Use Prettier for formatting
- Write JSDoc comments for public APIs
- Add tests for new features

---

## 🚢 Deployment

### Vercel (Recommended)

1. **Push to GitHub**

```bash
git push origin main
```

2. **Import project in Vercel**

- Go to [Vercel](https://vercel.com)
- Click "New Project"
- Import your GitHub repository
- Configure environment variables
- Deploy!

### Environment Variables for Production

```env
DATABASE_URL="postgresql://..."
NEXTAUTH_URL="https://yourdomain.com"
NEXTAUTH_SECRET="your-production-secret"
SOLANA_CLUSTER="mainnet-beta"
SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"
```

### Database Migration

```bash
# Run migrations in production
pnpm prisma migrate deploy
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'feat: Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass
- Follow semantic commit messages

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Solana](https://solana.com/) - The blockchain platform
- [Google ADK](https://github.com/google/agentic-ai-devkit) - Agent Development Kit
- [x402 Protocol](https://x402.dev/) - Payment Required Protocol
- [Next.js](https://nextjs.org/) - The React framework
- [Prisma](https://www.prisma.io/) - The database toolkit

---

## 📞 Contact & Support

- **GitHub**: [@0xsupremedev](https://github.com/0xsupremedev)
- **Email**: 0xsupremedev@gmail.com
- **Website**: [supremedev.vercel.app](https://supremedev.vercel.app)

---

<div align="center">

**Built with ❤️ by [0xsupremedev](https://github.com/0xsupremedev)**

[⭐ Star this repo](https://github.com/0xsupremedev/solwave-x402-adk) • [🐛 Report Bug](https://github.com/0xsupremedev/solwave-x402-adk/issues) • [💡 Request Feature](https://github.com/0xsupremedev/solwave-x402-adk/issues)

</div>
