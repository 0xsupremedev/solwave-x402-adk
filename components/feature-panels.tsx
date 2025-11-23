"use client";

import { Coins, Brain, Link2, ArrowRight } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";

export function FeaturePanels() {
  return (
    <section id="features" className="py-24 container">
      <div className="text-center mb-16">
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-sentient mb-4">
          The future of commerce is <i className="font-light">agent-to-agent</i>
        </h2>
        <p className="font-mono text-xs sm:text-sm text-blue-300 text-balance max-w-2xl mx-auto px-4 sm:px-0">
          x402 unlocks autonomous payment flows where agents can request, verify, and execute cryptocurrency payments in real time — no manual steps, no API sprawl, no centralized control. Powered by Solana devnet/mainnet, SPL tokens, USDC, Google ADK, and x402 Payment Required Protocol.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8">
        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Coins className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-sentient">Solana Integration</CardTitle>
            <CardDescription className="font-mono">
              Build AI agents that can transact natively on Solana.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 font-mono text-sm text-foreground/80">
              <li>• Real x402 payments on Solana devnet & mainnet</li>
              <li>• Automatic SOL/USDC devnet airdrop for testing</li>
              <li>• Integrated Phantom / Solflare wallet flow</li>
              <li>• On-chain transaction verification and explorer links</li>
              <li>• Instant settlement with USDC SPL tokens</li>
            </ul>
            <div className="flex gap-2 pt-4">
              <Button variant="default" size="sm" className="flex-1">
                Check Solana Account
              </Button>
              <Button variant="default" size="sm" className="flex-1">
                Test x402 Payment
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Brain className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-sentient">AI Tools & Agent Framework</CardTitle>
            <CardDescription className="font-mono">
              Everything you need to build revenue-generating autonomous agents.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 font-mono text-sm text-foreground/80">
              <li>• Preconfigured agents built with Google ADK</li>
              <li>• Merchant & buyer agent templates</li>
              <li>• Rich tools for actions, payments, sessions, tracing</li>
              <li>• MCP server, payment testing tools, debugging utilities</li>
              <li>• Local & cloud-based agent execution</li>
            </ul>
            <div className="flex gap-2 pt-4">
              <Button variant="default" size="sm" className="flex-1">
                Try Live Chat Agent
              </Button>
              <Button variant="default" size="sm" className="flex-1">
                Explore ADK Examples
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Link2 className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-sentient">x402 Payment Protocol</CardTitle>
            <CardDescription className="font-mono">
              The first payment spec designed for AI ↔ AI commerce.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 font-mono text-sm text-foreground/80">
              <li>• Machine-verifiable payment requests</li>
              <li>• Price negotiation or fixed pricing</li>
              <li>• Invoice lifecycle (pending → paid → settled)</li>
              <li>• Cryptographic signatures for trustless commerce</li>
              <li>• Built-in replay protection & expiry logic</li>
            </ul>
            <div className="flex gap-2 pt-4">
              <Button variant="default" size="sm" className="flex-1">
                Learn About x402
              </Button>
              <Button variant="default" size="sm" className="flex-1">
                Create Test Invoice
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

