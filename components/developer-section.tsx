"use client";

import { Code, FileCode, Wrench, BookOpen, Terminal, Bug, CheckCircle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";

export function DeveloperSection() {
  return (
    <section id="developers" className="py-24 container">
      <div className="text-center mb-16">
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-sentient mb-4">
          For <i className="font-light">Developers</i>
        </h2>
        <p className="font-mono text-xs sm:text-sm text-blue-300 text-balance max-w-2xl mx-auto px-4 sm:px-0">
          Everything you need to build autonomous payment-enabled agents
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-8 mb-8 sm:mb-12">
        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Code className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-xl font-sentient">SDKs & APIs</CardTitle>
            <CardDescription className="font-mono">
              REST & GraphQL APIs, JS/TS & Python SDKs, client & merchant libraries, webhooks for settlement, test harness for simulated payments.
            </CardDescription>
          </CardHeader>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <FileCode className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-xl font-sentient">Agent Templates</CardTitle>
            <CardDescription className="font-mono">
              Client/buyer agent, merchant agent, payment interpreter agent, verification agent, Telegram bot agent.
            </CardDescription>
          </CardHeader>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Wrench className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-xl font-sentient">Tools</CardTitle>
            <CardDescription className="font-mono">
              Live trace inspector, events/state viewer, session replay, invoice dashboard, signature debugger.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8">
        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="w-5 h-5" />
              Build With the Best Tools
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="font-sentient text-lg mb-2">Google ADK</h4>
              <p className="font-mono text-sm text-foreground/80">
                Build autonomous cognitive agents with full visibility into: state, tools, messages, remote agent interactions.
              </p>
            </div>
            <div>
              <h4 className="font-sentient text-lg mb-2">Solana Web3 Stack</h4>
              <p className="font-mono text-sm text-foreground/80">
                @solana/web3.js, SPL Token Program, Token 2022 support, devnet airdrop faucet, Solana RPC/Websocket listeners.
              </p>
            </div>
            <div>
              <h4 className="font-sentient text-lg mb-2">x402</h4>
              <p className="font-mono text-sm text-foreground/80">
                Spec-compliant payment requests for LLM-native commerce.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="w-5 h-5" />
              Quick Start
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 font-mono text-sm">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-primary" />
                <span>Install SDK: npm install @x402/solana-sdk</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-primary" />
                <span>Connect wallet: Phantom or Solflare</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-primary" />
                <span>Create invoice: createInvoice()</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-primary" />
                <span>Watch status: watchInvoice()</span>
              </div>
            </div>
            <Button variant="default" className="w-full mt-4">
              <BookOpen />
              Read the Docs
            </Button>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

