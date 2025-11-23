# SolWave - Solana x402 Google ADK Project Documentation

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Tech Stack](#architecture--tech-stack)
3. [Features Implemented](#features-implemented)
4. [UI/UX Components](#uiux-components)
5. [Wallet Integration](#wallet-integration)
6. [Payment Flow Implementation](#payment-flow-implementation)
7. [API Routes](#api-routes)
8. [Database Schema](#database-schema)
9. [Configuration & Environment](#configuration--environment)
10. [Documentation Pages](#documentation-pages)
11. [Styling & Theming](#styling--theming)
12. [Responsive Design](#responsive-design)
13. [Development Setup](#development-setup)

---

## 🎯 Project Overview

**SolWave** is an AI-powered payments platform for the autonomous web, built on Solana blockchain with x402 payment protocol integration and Google Agent Development Kit (ADK) support. The platform enables AI agents to request and process payments autonomously, facilitating agent-to-agent commerce.

### Key Technologies
- **Frontend**: Next.js 15.2.4, React 19, TypeScript
- **Blockchain**: Solana (mainnet-beta/devnet support)
- **Payment Protocol**: x402 Payment Required Protocol
- **Database**: SQLite with Prisma ORM
- **Authentication**: NextAuth.js
- **Styling**: Tailwind CSS 4.1.9
- **3D Graphics**: Three.js, React Three Fiber
- **Wallet Integration**: Solana Wallet Adapter

---

## 🏗️ Architecture & Tech Stack

### Frontend Architecture
- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript
- **State Management**: React Hooks, Zustand
- **UI Components**: Radix UI primitives
- **Styling**: Tailwind CSS with custom blue theme
- **3D Effects**: Three.js particle system with GLSL shaders

### Backend Architecture
- **API Routes**: Next.js API routes
- **Database**: Prisma ORM with SQLite
- **Authentication**: NextAuth.js with multiple providers
- **Payment Processing**: x402 protocol implementation
- **Blockchain Integration**: Solana Web3.js, SPL Token

### Agent Integration
- **ADK Tools**: Custom tools for payment requests
- **Client Agent**: Handles payment requests from user perspective
- **Merchant Agent**: Handles payment verification and settlement
- **MCP Server**: Merchant Control Plane for payment orchestration

---

## ✨ Features Implemented

### 1. Landing Page
- **Hero Section**: Eye-catching hero with animated particle background
- **Feature Panels**: Three main feature cards (Solana Integration, AI Tools, x402 Protocol)
- **Live Demo Section**: Interactive chat widget demonstration
- **How It Works**: Step-by-step process explanation
- **Developer Section**: SDK and API information
- **Telegram Section**: Bot integration showcase
- **Footer**: Social media links, legal pages, documentation links

### 2. Chat Dashboard (`/chat`)
- **Futuristic UI**: Neon-styled interface with dark blue theme
- **Integration Banner**: "x402 Solana Integration Active" pill banner
- **Welcome Section**: Dynamic welcome message
- **Feature Cards**: Solana Integration and AI Tools cards
- **Action Buttons**: Four quick action buttons with icons
  - Check Solana account
  - Test x402 payment
  - Generate random number
  - Say hello
- **Chat Input**: Auto-typing animation with blinking cursor
- **Model Selector**: Dropdown for selecting AI models (GPT 4o, GPT 3.5, Claude)

### 3. Documentation Pages (`/docs`)
- **Main Documentation Hub**: Comprehensive documentation with search
- **Quick Start Guide** (`/docs/quickstart`): NPM SDK installation and usage
- **Search Functionality**: Real-time search across documentation
- **Table of Contents**: 15 major sections with anchor links
- **Production-Ready**: All localhost references removed

### 4. Wallet Integration
- **Multi-Wallet Support**: 6 wallet adapters with priority ranking
  1. Phantom (Primary)
  2. Solflare
  3. Backpack
  4. Glow
  5. Slope
  6. Ledger
- **Wallet Provider**: React context provider for wallet state
- **Wallet Button**: Connection/disconnection UI
- **Wallet Modal**: Wallet selection interface
- **Graceful Degradation**: Works even if wallet adapters aren't installed

### 5. Payment Flow
- **x402 Invoice Creation**: Generate payment invoices
- **Payment Request**: Client-side payment request generation
- **Transaction Building**: Solana transaction construction with ATA computation
- **Payment Confirmation**: On-chain verification and confirmation
- **Payment Proof**: Send proof back to AI agents
- **Memo Encoding**: Invoice ID in transaction memos for security

### 6. Agent Tools
- **request_payment**: Generate x402 payment requests
- **wait_for_payment**: Poll for payment confirmation
- **verify_payment**: Verify on-chain transactions
- **create_invoice**: Create payment invoices
- **poll_invoice_status**: Check invoice status

---

## 🎨 UI/UX Components

### Core Components

#### 1. Header (`components/header.tsx`)
- **Logo**: SolWave branding with wave icon
- **Navigation**: Docs and Chats links with icons
- **External Links**: GitHub, Telegram, Contact
- **Mobile Menu**: Responsive hamburger menu
- **Sign In Button**: Authentication trigger

#### 2. Footer (`components/footer.tsx`)
- **Transparent Design**: Blends with particle background
- **Four Sections**:
  - Product (Features, Pricing, Changelog)
  - Resources (Documentation, API, Support)
  - Legal (Terms, Privacy, Cookies)
  - Community (GitHub, Telegram, Discord)
- **Social Media Icons**: LinkedIn, Discord, YouTube with circular buttons
- **Copyright**: SolWave branding

#### 3. Hero Section (`components/hero.tsx`)
- **Animated Background**: Three.js particle system
- **Headline**: "AI-Powered Payments for the Autonomous Web"
- **Subheadline**: Descriptive tagline
- **CTA Buttons**: Three action buttons with icons
  - Start Building
  - Explore Documentation
  - Launch Telegram Bot

#### 4. Feature Panels (`components/feature-panels.tsx`)
- **Three Feature Cards**:
  - Solana Integration
  - AI Tools
  - x402 Payment Protocol
- **Icons**: Lucide React icons
- **Responsive Grid**: 1 column mobile, 2 tablet, 3 desktop

#### 5. Chat Dashboard (`components/chat-dashboard/`)
- **Main Container**: `chat-dashboard.tsx`
- **Integration Banner**: `integration-banner.tsx`
- **Welcome Section**: `welcome-section.tsx`
- **Feature Cards**: `feature-cards.tsx`
- **Action Buttons**: `action-buttons.tsx`
- **Chat Input**: `chat-input.tsx` with auto-typing

#### 6. Button Component (`components/ui/button.tsx`)
- **Pill-Shaped Glass UI**: Glassmorphism design
- **Rounded Full**: Soft rounded cyber buttons
- **Backdrop Blur**: Frosted glass effect
- **Neon Borders**: Blue glowing borders
- **Hover Effects**: Smooth transitions and glow

### Special Effects

#### Particle System (`components/gl/`)
- **Three.js Integration**: 3D particle rendering
- **GLSL Shaders**: Custom point material shader
- **Blue Theme**: Blue particles on dark background
- **Performance Optimized**: Efficient rendering

#### Auto-Typing Animation
- **Typewriter Effect**: Character-by-character typing
- **Multiple Sample Texts**: Cycles through 4 different prompts
- **Delete & Retype**: Continuous loop animation
- **Blinking Cursor**: Visual typing indicator
- **User Interaction**: Stops when user types

---

## 💼 Wallet Integration

### Architecture

#### Wallet Provider (`components/wallet/WalletProvider.tsx`)
- **React Context**: Wraps Solana wallet adapter providers
- **Connection Provider**: Manages Solana RPC connection
- **Wallet Provider**: Manages wallet state
- **Modal Provider**: Wallet selection modal
- **Graceful Fallback**: Works without wallet adapters installed

#### Wallet Button (`components/wallet/WalletButton.tsx`)
- **Connection State**: Shows connected/disconnected state
- **Wallet Info**: Displays wallet name and address
- **Disconnect**: Clean disconnection handler
- **Loading States**: Handles connection in progress

#### Wallet Modal (`components/wallet/WalletModal.tsx`)
- **Wallet Selection**: List of available wallets
- **Priority Ranking**: Shows wallets in order of preference
- **Installation Prompts**: Guides users to install wallets

### SDK Integration

#### Wallet Signer Interface (`lib/sdk/wallet/signers.ts`)
```typescript
interface WalletSigner {
  publicKey: PublicKey;
  signTransaction(tx: Transaction): Promise<Transaction>;
  signAllTransactions?(txs: Transaction[]): Promise<Transaction[]>;
}
```

#### Wallet Utilities (`lib/sdk/wallet/index.ts`)
- **Adapter to Signer**: Converts wallet adapter to signer interface
- **Wallet Detection**: Detects installed wallets
- **Connection Helpers**: Utility functions for wallet operations

### Payment Components

#### Pay With Wallet (`components/flows/PayWithWallet.tsx`)
- **Full Payment Flow**: Complete payment processing
- **Confirmation Dialog**: Shows payment details before signing
- **Transaction Building**: Constructs Solana transactions
- **Signing**: Uses wallet to sign transactions
- **Submission**: Submits to Solana network
- **Confirmation**: Waits for on-chain confirmation
- **Error Handling**: Comprehensive error management

#### Payment Confirmation (`components/flows/PaymentConfirmation.tsx`)
- **Payment Details**: Shows amount, token, recipient
- **Network Info**: Displays Solana network
- **Fee Estimation**: Shows transaction fees
- **Approve/Cancel**: User confirmation buttons

---

## 💳 Payment Flow Implementation

### Transaction Building (`lib/sdk/payments/buildTransaction.ts`)

#### Features
- **ATA Computation**: Automatic Associated Token Account handling
- **SPL Token Support**: USDC and other SPL tokens
- **SOL Transfer**: Native SOL payment support
- **Memo Encoding**: Invoice ID in transaction memo
- **Blockhash Management**: Fresh blockhash fetching
- **Fee Payer**: Sets transaction fee payer

#### Security
- **Invoice Validation**: Validates x402 invoice before building
- **Amount Verification**: Ensures correct payment amounts
- **Recipient Validation**: Verifies recipient addresses
- **Expiry Checking**: Enforces invoice expiration

### Payment Confirmation (`lib/sdk/payments/confirmPayment.ts`)

#### Process
1. **Submit Transaction**: Send signed transaction to network
2. **Wait for Confirmation**: Poll for transaction confirmation
3. **Verify Status**: Check transaction status
4. **Return Receipt**: Provide confirmation details

### Payment Proof (`lib/sdk/agents/sendPaymentProof.ts`)

#### Proof Structure
```typescript
interface PaymentProof {
  invoiceId: string;
  signature: string;
  payer: string;
  amount: string;
  token: string;
  confirmed: boolean;
  confirmedAt: string;
  blockTime?: number;
  slot?: number;
}
```

### Invoice Validation (`lib/sdk/payments/validateInvoice.ts`)
- **Amount Validation**: Ensures positive amounts
- **Token Validation**: Verifies token mint addresses
- **Expiry Check**: Validates invoice expiration
- **Recipient Check**: Verifies recipient addresses
- **Nonce Validation**: Prevents replay attacks

### Memo Utilities (`lib/sdk/utils/memo.ts`)
- **Encoding**: Encodes invoice ID into memo format
- **Decoding**: Extracts invoice ID from memo
- **Memo Program**: Uses Solana Memo Program
- **Prefix**: `x402:` prefix for identification

---

## 🔌 API Routes

### Invoice Management

#### `POST /api/v1/invoices`
- **Purpose**: Create new payment invoices
- **Body**: `{ merchantId, amount, token, metadata }`
- **Response**: Invoice object with ID and status

#### `GET /api/v1/invoices`
- **Purpose**: List invoices with filters
- **Query Params**: `merchantId`, `status`, `limit`, `offset`
- **Response**: Array of invoice objects

#### `GET /api/v1/invoices/[id]`
- **Purpose**: Get specific invoice details
- **Response**: Invoice object with current status

#### `POST /api/v1/invoices/[id]`
- **Purpose**: Update invoice status
- **Body**: `{ txSignature, status }`
- **Validation**: Zod schema validation
- **Response**: Updated invoice object

### Webhook Management

#### `POST /api/v1/webhooks/register`
- **Purpose**: Register merchant webhooks
- **Body**: `{ merchantId, url, events }`
- **Response**: Webhook registration confirmation

### Agent Sessions

#### `GET /api/v1/agents/[id]/sessions`
- **Purpose**: Retrieve agent session data
- **Response**: Session information and history

### Authentication

#### `POST /api/auth/signup`
- **Purpose**: User registration
- **Body**: `{ email, password, name }`
- **Response**: User object

#### NextAuth Routes (`/api/auth/[...nextauth]`)
- **Providers**: Google, GitHub OAuth
- **Database**: Prisma adapter
- **Session**: JWT or database sessions

---

## 🗄️ Database Schema

### Prisma Models

#### User Model
```prisma
model User {
  id            String    @id @default(cuid())
  email         String    @unique
  name          String?
  passwordHash  String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  accounts      Account[]
  sessions      Session[]
  merchants     Merchant[]
}
```

#### Merchant Model
```prisma
model Merchant {
  id            String    @id @default(cuid())
  userId        String
  name          String
  publicKey     String    @unique
  webhookUrl    String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  user          User      @relation(fields: [userId], references: [id])
  invoices      Invoice[]
}
```

#### Invoice Model
```prisma
model Invoice {
  id            String    @id @default(cuid())
  merchantId    String
  amount        String
  token         String    @default("USDC")
  status        String    @default("PENDING")
  txSignature   String?
  nonce         String    @unique
  expiresAt     DateTime
  metadata      String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  merchant      Merchant  @relation(fields: [merchantId], references: [id])
}
```

#### AgentSession Model
```prisma
model AgentSession {
  id            String    @id @default(cuid())
  agentId       String
  sessionData   String    @type(Json)
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
}
```

---

## ⚙️ Configuration & Environment

### Environment Variables

#### Frontend
```env
NEXT_PUBLIC_API_BASE_URL=https://api.yourdomain.com
NEXT_PUBLIC_ADK_ENDPOINT=https://adk.yourdomain.com
NEXT_PUBLIC_SOLANA_NETWORK=mainnet-beta
NEXT_PUBLIC_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
NEXT_PUBLIC_DEFAULT_TOKEN_USDC=USDC_MAINNET_MINT_ADDRESS
```

#### Backend
```env
DATABASE_URL=file:./dev.db
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-secret-key
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

#### Solana Configuration
```env
SOLANA_CLUSTER=mainnet-beta
SOLANA_RPC=https://api.mainnet-beta.solana.com
USDC_MINT_ADDRESS=<USDC_MAINNET_MINT>
```

### Next.js Configuration (`next.config.mjs`)

#### Features
- **TypeScript**: Build errors ignored for development
- **Images**: Unoptimized for faster builds
- **Webpack**: Custom configuration for optional wallet adapters
- **Module Resolution**: Handles missing wallet adapter packages gracefully

#### Webpack Configuration
- **Optional Dependencies**: Wallet adapters are optional
- **Stub Module**: Fallback for missing packages
- **Client-Side Only**: Wallet adapters only on client

---

## 📚 Documentation Pages

### Main Documentation (`/docs`)

#### Sections
1. **Overview**: Project introduction
2. **Architecture & Components**: System design
3. **Prerequisites**: Required tools
4. **Getting Started**: Setup instructions
5. **Configuration**: Environment variables
6. **Solana Integration**: Wallet flow documentation
7. **x402 Protocol**: Payment protocol explanation
8. **MCP Server**: Agent integration
9. **API Reference**: Complete API documentation
10. **Example Flows**: Walkthroughs
11. **Testing & Debugging**: Testing guide
12. **Security Considerations**: Security best practices
13. **Deployment**: Production deployment
14. **Contributing**: Contribution guidelines
15. **License**: License information

#### Features
- **Search Functionality**: Real-time search across documentation
- **Anchor Links**: Smooth scrolling to sections
- **Code Examples**: Syntax-highlighted code blocks
- **Responsive Design**: Mobile-friendly layout

### Quick Start Guide (`/docs/quickstart`)

#### Content
- **NPM SDK Installation**: Package installation
- **Wallet Connection**: Wallet adapter setup
- **Create Invoice**: Invoice creation examples
- **Watch Invoice**: Status monitoring
- **Code Examples**: TypeScript/JavaScript snippets

---

## 🎨 Styling & Theming

### Color Scheme

#### Primary Colors
- **Background**: Deep blue (`#0a1628`, `blue-950`)
- **Borders**: Blue with opacity (`blue-500/50`)
- **Text**: Blue tones (`blue-200`, `blue-300`, `blue-400`)
- **Accents**: Bright blue (`blue-400`, `blue-500`)

#### Theme Variables (`app/globals.css`)
```css
--background: #0a1628
--foreground: #e0e7ff
--primary: #3b82f6
--border: rgba(59, 130, 246, 0.5)
```

### Typography

#### Fonts
- **Body**: Geist Mono (monospace)
- **Headings**: Sentient font family
- **Code**: Monospace font stack

#### Font Sizes
- **Mobile**: Responsive text sizing
- **Desktop**: Larger headings and body text
- **Code**: Consistent monospace sizing

### Component Styles

#### Buttons
- **Pill Shape**: `rounded-full`
- **Glass Effect**: `backdrop-blur-md`
- **Borders**: `border-blue-500/50`
- **Hover**: Enhanced glow and border brightness

#### Cards
- **Background**: `bg-blue-950/40`
- **Borders**: `border-blue-500/50`
- **Backdrop**: `backdrop-blur-sm`
- **Shadows**: Blue-tinted shadows

#### Inputs
- **Background**: `bg-blue-900/30`
- **Borders**: `border-blue-500/50`
- **Focus**: `focus:border-blue-400/70`
- **Placeholder**: `placeholder:text-blue-400/40`

---

## 📱 Responsive Design

### Breakpoints

#### Mobile (< 640px)
- **Single Column**: All layouts stack vertically
- **Small Text**: Reduced font sizes
- **Compact Spacing**: Tighter padding and margins
- **Hidden Elements**: Some decorative elements hidden

#### Tablet (640px - 1024px)
- **Two Columns**: Grid layouts use 2 columns
- **Medium Text**: Moderate font sizes
- **Balanced Spacing**: Standard padding

#### Desktop (> 1024px)
- **Multi-Column**: Full grid layouts
- **Large Text**: Maximum font sizes
- **Generous Spacing**: Comfortable padding

### Responsive Components

#### Header
- **Mobile**: Hamburger menu
- **Desktop**: Full navigation bar

#### Footer
- **Mobile**: Stacked sections
- **Desktop**: Four-column layout

#### Feature Panels
- **Mobile**: 1 column
- **Tablet**: 2 columns
- **Desktop**: 3 columns

#### Action Buttons
- **Mobile**: 1 column, full width
- **Tablet**: 2 columns
- **Desktop**: 4 columns

#### Chat Dashboard
- **Mobile**: Compact layout
- **Desktop**: Spacious layout with all features visible

---

## 🛠️ Development Setup

### Prerequisites
- Node.js 18+
- pnpm (or npm/yarn)
- Git
- Solana CLI (optional)

### Installation

```bash
# Clone repository
git clone <repository-url>
cd "solana x402 google ADK"

# Install dependencies
pnpm install

# Setup database
pnpm prisma generate
pnpm prisma migrate dev

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration

# Run development server
pnpm dev
```

### Project Structure

```
solana-x402-google-adk/
├── app/                    # Next.js app directory
│   ├── api/               # API routes
│   ├── chat/              # Chat dashboard page
│   ├── docs/              # Documentation pages
│   ├── layout.tsx         # Root layout
│   └── page.tsx           # Landing page
├── components/            # React components
│   ├── chat-dashboard/   # Chat dashboard components
│   ├── wallet/           # Wallet integration
│   ├── flows/            # Payment flow components
│   └── ui/               # UI primitives
├── lib/                   # Utility libraries
│   ├── sdk/              # SDK implementation
│   ├── solana/           # Solana utilities
│   ├── x402/             # x402 protocol
│   └── adk/              # ADK tools and agents
├── prisma/               # Database schema
├── public/               # Static assets
└── docs.md              # This documentation
```

### Key Dependencies

#### Core
- `next@15.2.4`: React framework
- `react@19`: UI library
- `typescript@5`: Type safety

#### Blockchain
- `@solana/web3.js@^1.98.4`: Solana blockchain
- `@solana/spl-token@^0.4.14`: SPL token support
- `@solana/wallet-adapter-*`: Wallet integrations

#### Database
- `prisma@^6.19.0`: ORM
- `@prisma/client@^6.19.0`: Prisma client

#### UI
- `tailwindcss@^4.1.9`: Styling
- `@radix-ui/*`: UI primitives
- `lucide-react@^0.454.0`: Icons
- `three@latest`: 3D graphics
- `@react-three/fiber@latest`: React Three.js

#### Authentication
- `next-auth@^4.24.13`: Authentication
- `@next-auth/prisma-adapter@^1.0.7`: Prisma adapter

---

## 🔐 Security Features

### Payment Security
- **Invoice Validation**: All invoices validated before processing
- **Nonce Protection**: Replay attack prevention
- **Expiry Enforcement**: Time-based invoice expiration
- **On-Chain Verification**: All payments verified on-chain
- **Memo Encoding**: Invoice ID in transaction memo
- **Amount Verification**: Payment amounts verified

### Application Security
- **Environment Variables**: Sensitive data in env vars
- **Input Validation**: Zod schema validation
- **SQL Injection Prevention**: Prisma ORM protection
- **XSS Prevention**: React's built-in protection
- **CSRF Protection**: NextAuth.js CSRF tokens

---

## 🚀 Deployment Considerations

### Production Checklist
- [ ] Environment variables configured
- [ ] Database migrations run
- [ ] Solana network set to mainnet-beta
- [ ] Wallet adapter packages installed
- [ ] API endpoints secured
- [ ] Error tracking configured
- [ ] Monitoring set up
- [ ] SSL/TLS certificates configured
- [ ] CDN configured for static assets

### Recommended Platforms
- **Frontend**: Vercel, Netlify
- **Database**: PostgreSQL (production), SQLite (development)
- **Monitoring**: Sentry, LogRocket
- **Analytics**: Vercel Analytics

---

## 📝 Notes

### Wallet Adapter Installation
The project is designed to work even if wallet adapter packages aren't installed. See `WALLET_SETUP.md` for installation instructions.

### Development vs Production
- **Development**: Uses SQLite, devnet, localhost URLs
- **Production**: Should use PostgreSQL, mainnet, production URLs

### Future Enhancements
- [ ] Additional wallet support
- [ ] More payment tokens
- [ ] Advanced agent tools
- [ ] Analytics dashboard
- [ ] Webhook management UI
- [ ] Invoice management dashboard

---

## 📄 License

This project is part of the SolWave platform. Please refer to the project's LICENSE file for license information.

---

## 🤝 Contributing

Contributions are welcome! Please follow the project's contribution guidelines and submit pull requests for any improvements.

---

**Last Updated**: November 18, 2025
**Version**: 1.0.0
**Project**: SolWave - Solana x402 Google ADK

