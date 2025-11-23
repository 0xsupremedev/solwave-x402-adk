"use client";

import { DocsSearch } from "@/components/docs/search";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";
import { 
  BookOpen, 
  Code, 
  Bot, 
  FileText, 
  Settings, 
  Wallet, 
  Server, 
  Shield,
  Rocket,
  TestTube,
  Globe
} from "lucide-react";

const docSections = [
  {
    id: "overview",
    title: "Overview",
    icon: BookOpen,
    description: "Introduction to x402 AI Starter Kit (Solana Edition)",
  },
  {
    id: "architecture",
    title: "Architecture & Components",
    icon: Code,
    description: "System architecture and component overview",
  },
  {
    id: "prerequisites",
    title: "Prerequisites",
    icon: Settings,
    description: "Required tools and dependencies",
  },
  {
    id: "getting-started",
    title: "Getting Started",
    icon: Rocket,
    description: "Setup and deployment guide",
  },
  {
    id: "configuration",
    title: "Configuration & Environment Variables",
    icon: Settings,
    description: "Environment configuration guide",
  },
  {
    id: "solana",
    title: "Solana Integration & Wallet Flow",
    icon: Wallet,
    description: "Solana blockchain integration",
  },
  {
    id: "x402",
    title: "x402 Payment Protocol Explained",
    icon: FileText,
    description: "Understanding the x402 payment protocol",
  },
  {
    id: "mcp",
    title: "MCP Server & Agent Integration",
    icon: Server,
    description: "MCP server setup and agent integration",
  },
  {
    id: "api",
    title: "API Reference",
    icon: Code,
    description: "Complete API documentation",
  },
  {
    id: "examples",
    title: "Example Flows / Walkthroughs",
    icon: Bot,
    description: "Step-by-step examples and tutorials",
  },
  {
    id: "testing",
    title: "Testing & Debugging",
    icon: TestTube,
    description: "Testing and debugging guide",
  },
  {
    id: "security",
    title: "Security Considerations",
    icon: Shield,
    description: "Security best practices",
  },
  {
    id: "deployment",
    title: "Deployment",
    icon: Globe,
    description: "Deployment instructions",
  },
];

export default function DocsPage() {
  return (
    <div className="container py-12 sm:py-16">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl sm:text-5xl font-sentient mb-4 text-white">
            x402 AI Starter Kit — Documentation
          </h1>
          <p className="font-mono text-blue-300 text-balance max-w-2xl mx-auto mb-8">
            Welcome to the x402 AI Starter Kit (Solana Edition) documentation. This document provides a detailed, end-to-end guide to the starter kit: architecture, installation, configuration, developer workflows, payment flows using x402 on Solana, API references, examples, troubleshooting, and deployment instructions.
          </p>
          
          {/* Search */}
          <div className="flex justify-center">
            <DocsSearch />
          </div>
        </div>

        {/* Quick Start Section */}
        <div className="mb-12">
          <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
            <CardContent className="p-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-blue-900/50 flex items-center justify-center flex-shrink-0">
                  <Rocket className="w-6 h-6 text-blue-400" />
                </div>
                <div className="flex-1">
                  <h2 className="font-sentient text-2xl mb-2 text-white">Quick Start</h2>
                  <p className="font-mono text-sm text-blue-200 mb-4">
                    Get started with the NPM SDK in minutes
                  </p>
                  <Link 
                    href="/docs/quickstart"
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-900/50 border border-blue-500/50 text-blue-200 hover:bg-blue-800/50 hover:border-blue-400/70 transition-all font-mono text-sm"
                  >
                    View Quick Start Guide
                    <Rocket className="w-4 h-4" />
                  </Link>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Table of Contents */}
        <div className="mb-12">
          <h2 className="font-sentient text-3xl mb-6 text-white">Table of Contents</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {docSections.map((section) => {
              const Icon = section.icon;
              return (
                <Link
                  key={section.id}
                  href={`/docs#${section.id}`}
                  className="group"
                >
                  <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm hover:border-blue-400/70 hover:bg-blue-900/50 transition-all h-full">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-blue-900/50 flex items-center justify-center flex-shrink-0 group-hover:bg-blue-800/50 transition-colors">
                          <Icon className="w-5 h-5 text-blue-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <h3 className="font-sentient text-lg mb-1 text-white group-hover:text-blue-100 transition-colors">
                            {section.title}
                          </h3>
                          <p className="font-mono text-xs text-blue-300/80 line-clamp-2">
                            {section.description}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              );
            })}
          </div>
        </div>

        {/* Overview Section */}
        <section id="overview" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">1. Overview</h2>
          <div className="prose prose-invert max-w-none">
            <p className="font-mono text-blue-200 mb-4">
              The x402 AI Starter Kit (Solana Edition) is a reference application demonstrating how AI agents (built with an Agent Development Kit) can request and process payments using the x402 protocol and the Solana blockchain. The starter kit includes:
            </p>
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li>A Next.js web UI providing a friendly front-end for testing and interacting with agents.</li>
              <li>AI tools panel and pre-built agent flows (client/merchant patterns).</li>
              <li>An MCP (merchant control plane) server component for account provisioning and payment orchestration.</li>
              <li>Example integrations showing how to create, sign, and confirm Solana transactions (SOL / USDC) in response to x402 payment requests.</li>
            </ul>
            <p className="font-mono text-blue-200 mt-4">
              This kit is ideal for developers building pay-to-use AI services, agent-to-agent commerce, or experimenting with decentralized payment coordination using x402 + Solana.
            </p>
          </div>
        </section>

        {/* Architecture Section */}
        <section id="architecture" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">2. Architecture & Components</h2>
          <div className="space-y-4">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">High-level components:</h3>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li><strong>Next.js Frontend ( / )</strong>: UI for interacting with agents, quick actions (Check Solana account, Test x402 payment), model selector, and chat interface.</li>
                <li><strong>MCP Server ( /mcp )</strong>: Backend service that manages accounts, issues x402 requests, and orchestrates payment transactions for merchants.</li>
                <li><strong>ADK Agents</strong>: Client agent and merchant agent examples that run A2A (agent-to-agent) flows using the ADK library.</li>
                <li><strong>Solana Blockchain</strong>: The blockchain environment for production transactions on Solana mainnet.</li>
              </ul>
            </div>
            <div className="mt-6">
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Flow overview:</h3>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li>User interacts with the Frontend (eg. "I want to buy banana").</li>
                <li>Client Agent constructs an x402 payment request targeted at the Merchant Agent.</li>
                <li>Merchant Agent responds with payment instructions (amount, token, address, or a prepared transaction).</li>
                <li>Client signs and submits the transaction to Solana (via wallet / MCP helper / simulated signer).</li>
                <li>Merchant confirms payment and completes the service.</li>
              </ol>
            </div>
          </div>
        </section>

        {/* Prerequisites Section */}
        <section id="prerequisites" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">3. Prerequisites</h2>
          <div className="space-y-4">
            <p className="font-mono text-blue-200 mb-4">
              Before you begin, install the following on your machine:
            </p>
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li>Node.js (v18+ recommended) and npm/yarn</li>
              <li>Git</li>
              <li>Docker (optional, useful for MCP server deployment)</li>
              <li>Solana CLI (for advanced blockchain interactions)</li>
              <li>A wallet integration (eg. Phantom or Solflare) for signing transactions</li>
            </ul>
            <div className="mt-6">
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Recommended dev tools:</h3>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li>VS Code</li>
                <li>Postman / Insomnia (for API testing)</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Getting Started Section */}
        <section id="getting-started" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">4. Getting Started</h2>
          <div className="space-y-6">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">1. Clone the repo</h3>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`git clone <REPO_URL>
cd x402-ai-starter-kit`}
              </pre>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">2. Install dependencies</h3>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`# in the root directory (Next.js frontend)
npm install

# if MCP server has a separate package
cd mcp-server && npm install`}
              </pre>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">3. Configure environment variables</h3>
              <p className="font-mono text-sm text-blue-200 mb-2">
                See the Configuration section below for full details on the env variables. Configure your environment variables in your hosting platform or deployment environment.
              </p>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">4. Deploy the application</h3>
              <p className="font-mono text-sm text-blue-200 mb-2">Deploy the application to your hosting platform:</p>
              <ul className="space-y-1 font-mono text-sm text-blue-200 list-disc list-inside ml-4 mb-4">
                <li>Deploy Next.js frontend to Vercel or your preferred platform</li>
                <li>Deploy MCP server to your backend infrastructure</li>
                <li>Configure production environment variables</li>
              </ul>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">5. Configure agents</h3>
              <p className="font-mono text-sm text-blue-200 mb-2">
                Set up your ADK agents with production credentials and configuration. Agents will register in the ADK environment and can be invoked from the UI.
              </p>
            </div>
          </div>
        </section>

        {/* Configuration Section */}
        <section id="configuration" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">5. Configuration & Environment Variables</h2>
          <div className="space-y-6">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Frontend Environment Variables</h3>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`NEXT_PUBLIC_API_BASE_URL=https://api.yourdomain.com # MCP server address
NEXT_PUBLIC_ADK_ENDPOINT=https://adk.yourdomain.com # ADK or agent endpoint
NEXT_PUBLIC_SOLANA_NETWORK=mainnet-beta
NEXT_PUBLIC_DEFAULT_TOKEN_USDC=USDC_MAINNET_MINT_ADDRESS`}
              </pre>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">MCP Server Environment Variables</h3>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`PORT=4000
SOLANA_CLUSTER=mainnet-beta
SOLANA_RPC=https://api.mainnet-beta.solana.com
USDC_MINT_ADDRESS=<USDC_MAINNET_MINT>`}
              </pre>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Agent configuration</h3>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li><strong>AGENT_ID / AGENT_TOKEN</strong> (ADK authentication)</li>
                <li><strong>MERCHANT_PUBLIC_KEY</strong> — the Solana address merchants use to receive payments</li>
              </ul>
              <p className="font-mono text-sm text-blue-200 mt-4">
                <strong>Keep secrets (private keys, service tokens) out of git and use environment variables or secret managers.</strong>
              </p>
            </div>
          </div>
        </section>

        {/* Solana Integration Section */}
        <section id="solana" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">6. Solana Integration & Wallet Flow</h2>
          <div className="space-y-6">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Supported Wallets</h3>
              <p className="font-mono text-sm text-blue-200 mb-3">
                The SDK supports 6 major Solana wallets with priority ranking:
              </p>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li><strong>Phantom</strong> - Most popular Solana wallet</li>
                <li><strong>Solflare</strong> - Strong DeFi presence</li>
                <li><strong>Backpack</strong> - Essential for xNFT ecosystem</li>
                <li><strong>Glow</strong> - Light, fast, mobile-friendly</li>
                <li><strong>Slope</strong> - Popular in Asia markets</li>
                <li><strong>Ledger</strong> - Enterprise-grade hardware wallet</li>
              </ol>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Wallet Integration Architecture</h3>
              <p className="font-mono text-sm text-blue-200 mb-3">
                The wallet integration uses a <strong>WalletSigner interface abstraction</strong> that decouples SDK logic from UI wallet adapter implementation. This ensures:
              </p>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li>SDK works with any wallet implementing the interface</li>
                <li>No direct wallet object dependencies</li>
                <li>Clean separation of concerns</li>
                <li>Easy testing and mocking</li>
              </ul>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Wallet Connection Flow</h3>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li>Frontend detects installed wallets automatically</li>
                <li>Wallet adapter ranks wallets by priority (Phantom → Solflare → Backpack → Glow → Slope → Ledger)</li>
                <li>User selects wallet or auto-connects to highest priority</li>
                <li>Wallet adapter provides WalletSigner interface to SDK</li>
                <li>SDK uses signer for transaction signing</li>
              </ol>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Payment Flow with Wallets</h3>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li>AI agent generates x402 payment request</li>
                <li>Frontend receives and displays payment confirmation dialog</li>
                <li>SDK builds transaction from x402 payload (validates, computes ATA, adds memo)</li>
                <li>Wallet signs transaction (user approves in wallet popup)</li>
                <li>SDK submits transaction to Solana RPC</li>
                <li>SDK waits for on-chain confirmation</li>
                <li>Payment proof sent back to AI agent</li>
                <li>Merchant agent verifies payment and completes order</li>
              </ol>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">USDC / Token flow</h3>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li>Merchant requests payment: 5 USDC to merchant_address.</li>
                <li>Client prepares a token transfer or uses Solana Pay / associated token accounts.</li>
                <li>Client signs the transfer and submits to Solana RPC.</li>
                <li>Merchant watches the transaction signature; once confirmed, service is delivered.</li>
              </ol>
            </div>
          </div>
        </section>

        {/* x402 Protocol Section */}
        <section id="x402" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">7. x402 Payment Protocol Explained</h2>
          <div className="space-y-4">
            <p className="font-mono text-blue-200">
              x402 is a lightweight extension of HTTP payment semantics for agent-to-agent commerce. The important concepts in starter kit context:
            </p>
            <ul className="space-y-3 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li><strong>Payment Request</strong>: An agent (merchant) responds to a service invocation with an x402 payment requirement (amount, token, target address, optional prepared transaction, expiration).</li>
              <li><strong>Payment Response</strong>: The payer (client) either approves and signs a transaction, or returns a proof-of-payment after submission.</li>
              <li><strong>Receipt/Confirmation</strong>: Merchant validates the transaction on-chain and completes the requested action.</li>
            </ul>
            <div className="mt-6">
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Typical fields in an x402 payload:</h3>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`{
  "amount": "5000",
  "currency": "USDC",
  "token_mint": "<USDC_MINT_ADDRESS>",
  "recipient": "<merchant_sol_address>",
  "memo": "x402-payment-for:banana-order-123",
  "expires_at": "2025-01-01T00:00:00Z",
  "prepared_tx": "<optional_base64_serialized_tx>"
}`}
              </pre>
              <p className="font-mono text-sm text-blue-200 mt-4">
                <strong>Prepared transaction mode</strong>: the merchant may provide a prepared transaction (unsigned or partially signed) for the payer to sign and submit.
              </p>
              <p className="font-mono text-sm text-blue-200 mt-2">
                <strong>Security note</strong>: Never rely solely on off-chain signals for payment completion; always validate on-chain confirmations and expected token amounts.
              </p>
            </div>
          </div>
        </section>

        {/* MCP Server Section */}
        <section id="mcp" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">8. MCP Server & Agent Integration</h2>
          <div className="space-y-6">
            <p className="font-mono text-blue-200">
              The MCP server exposes endpoints that agents and the frontend use for payment orchestration. Core endpoints include:
            </p>
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li><strong>POST /prepare-payment</strong> — merchant requests the server prepare a transaction payload</li>
              <li><strong>POST /validate-payment</strong> — merchant asks server to validate payment using transaction signature</li>
              <li><strong>GET /health</strong> — service health check</li>
            </ul>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">MCP responsibilities</h3>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li>Orchestrate payment transactions</li>
                <li>Offer prepared transaction generation</li>
                <li>Provide payment validation services</li>
              </ul>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Agent interactions</h3>
              <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
                <li>Agents call MCP for payment orchestration and transaction preparation</li>
                <li>Frontend triggers agent invocations via ADK endpoints; agents in turn orchestrate with MCP</li>
              </ul>
            </div>
          </div>
        </section>

        {/* API Reference Section */}
        <section id="api" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">9. API Reference</h2>
          <div className="space-y-6">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">GET /health</h3>
              <p className="font-mono text-sm text-blue-200">Returns service health and Solana cluster connectivity.</p>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">POST /prepare-payment</h3>
              <p className="font-mono text-sm text-blue-200 mb-2">Create a prepared transaction for token transfer</p>
              <p className="font-mono text-xs text-blue-300 mb-2">Request:</p>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-xs overflow-x-auto text-blue-200 mb-2">
{`{
  "from": "payerPubkey",
  "to": "merchantPubkey",
  "amount": "5",
  "mint": "USDC_MINT"
}`}
              </pre>
              <p className="font-mono text-xs text-blue-300 mb-2">Response:</p>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-xs overflow-x-auto text-blue-200">
{`{ "preparedTxBase64": "...", "recentBlockhash": "..." }`}
              </pre>
            </div>
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">POST /validate-payment</h3>
              <p className="font-mono text-sm text-blue-200 mb-2">Validate a tx signature and token transfer</p>
              <p className="font-mono text-xs text-blue-300 mb-2">Request:</p>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-xs overflow-x-auto text-blue-200 mb-2">
{`{ "signature": "...", "expectedAmount": 5, "mint": "USDC_MINT" }`}
              </pre>
              <p className="font-mono text-xs text-blue-300 mb-2">Response:</p>
              <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-xs overflow-x-auto text-blue-200">
{`{ "status": "confirmed", "confirmedSlot": 12345 }`}
              </pre>
            </div>
            <p className="font-mono text-xs text-blue-400/60 italic">
              This is a compact reference — adapt to your actual code routes.
            </p>
          </div>
        </section>

        {/* Examples Section */}
        <section id="examples" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">10. Example Flows / Walkthroughs</h2>
          <div className="space-y-8">
            <div>
              <h3 className="font-sentient text-xl mb-3 text-blue-100">Example 1 — Basic buyer flow (UI + Phantom wallet)</h3>
              <ol className="space-y-2 font-mono text-sm text-blue-200 list-decimal list-inside ml-4">
                <li>User types in the UI: "I want to buy banana".</li>
                <li>Client agent constructs a purchase intent and asks merchant agent for price.</li>
                <li>Merchant replies with x402 payment request: 5 USDC to merchantAddress.</li>
                <li>Frontend opens Phantom signature modal with a token transfer transaction (or uses prepare-payment to get a prepared transaction).</li>
                <li>User confirms and signs in Phantom; the tx is submitted to Solana.</li>
                <li>Merchant observes the tx signature, validates token amount, and replies: "Your order is being prepared".</li>
              </ol>
            </div>
          </div>
        </section>

        {/* Testing Section */}
        <section id="testing" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">11. Testing & Debugging</h2>
          <div className="space-y-4">
            <p className="font-mono text-blue-200">
              For monitoring and debugging, use the following approaches:
            </p>
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li>Monitor transactions via Solana Explorer</li>
              <li>Check MCP server logs for payment orchestration</li>
              <li>Use browser DevTools to inspect agent interactions</li>
              <li>Set up proper logging and monitoring infrastructure</li>
              <li>Use error tracking services for production issues</li>
            </ul>
          </div>
        </section>

        {/* Security Section */}
        <section id="security" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">12. Security Considerations</h2>
          <div className="space-y-4">
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li>Never use server signing in production — always require user wallet signatures</li>
              <li>Validate all on-chain transactions before completing services</li>
              <li>Use proper key management — never commit private keys to git</li>
              <li>Implement rate limiting on API endpoints</li>
              <li>Use HTTPS in production</li>
              <li>Validate payment amounts and recipients on-chain</li>
              <li>Implement proper error handling and logging</li>
            </ul>
          </div>
        </section>

        {/* Deployment Section */}
        <section id="deployment" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">13. Deployment (Vercel & Production Tips)</h2>
          <div className="space-y-4">
            <p className="font-mono text-blue-200">
              For deployment to Vercel or other platforms:
            </p>
            <ul className="space-y-2 font-mono text-sm text-blue-200 list-disc list-inside ml-4">
              <li>Set all environment variables in your hosting platform</li>
              <li>Use production Solana cluster (mainnet-beta) for live services</li>
              <li>Configure proper CORS settings</li>
              <li>Set up monitoring and alerting</li>
              <li>Use environment-specific configuration</li>
              <li>Enable proper logging and error tracking</li>
              <li>Configure SSL/TLS certificates</li>
              <li>Set up CDN for static assets</li>
              <li>Implement rate limiting and DDoS protection</li>
            </ul>
          </div>
        </section>

        {/* Contributing Section */}
        <section id="contributing" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">14. Contributing</h2>
          <p className="font-mono text-blue-200">
            Contributions are welcome! Please follow the project's contribution guidelines and submit pull requests for any improvements.
          </p>
        </section>

        {/* License Section */}
        <section id="license" className="mb-16 scroll-mt-20">
          <h2 className="font-sentient text-3xl mb-6 text-white">15. License</h2>
          <p className="font-mono text-blue-200">
            Please refer to the project's LICENSE file for license information.
          </p>
        </section>
      </div>
    </div>
  );
}
