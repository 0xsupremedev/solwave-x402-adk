"use client";

import { ArrowRight, Wallet, Zap, CheckCircle, Package } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";

const steps = [
  {
    number: 1,
    title: "The agent requests payment",
    description: "Client agent sends an x402 request with item, amount, and merchant metadata.",
    icon: Wallet,
  },
  {
    number: 2,
    title: "User approves & signs",
    description: "User signs the transaction in Phantom/Solflare or via programmatic signing.",
    icon: CheckCircle,
  },
  {
    number: 3,
    title: "Solana processes the transaction",
    description: "Fast finality and cheap fees make it instant for AI-driven commerce.",
    icon: Zap,
  },
  {
    number: 4,
    title: "Merchant agent receives confirmation",
    description: "The merchant agent verifies the signature and continues the workflow.",
    icon: Package,
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="py-24 container">
      <div className="text-center mb-16">
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-sentient mb-4">
          How It <i className="font-light">Works</i>
        </h2>
        <p className="font-mono text-xs sm:text-sm text-blue-300 text-balance max-w-2xl mx-auto px-4 sm:px-0">
          A simple 4-step process for autonomous agent-to-agent commerce
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-8 sm:mb-12">
        {steps.map((step, index) => {
          const Icon = step.icon;
          return (
            <Card key={step.number} className="border-border bg-background/50 backdrop-blur-sm relative">
              <CardHeader>
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Icon className="w-6 h-6 text-primary" />
                  </div>
                  <span className="text-4xl font-sentient text-foreground/20">{step.number}</span>
                </div>
                <CardTitle className="text-xl font-sentient">{step.title}</CardTitle>
                <CardDescription className="font-mono text-sm">
                  {step.description}
                </CardDescription>
              </CardHeader>
              {index < steps.length - 1 && (
                <div className="hidden md:block absolute top-1/2 -right-3 transform -translate-y-1/2">
                  <ArrowRight className="w-6 h-6 text-primary/50" />
                </div>
              )}
            </Card>
          );
        })}
      </div>

      <div className="text-center">
        <Card className="border-border bg-background/50 backdrop-blur-sm inline-block">
          <CardContent className="p-6">
            <p className="font-mono text-foreground/80">
              Issue item • Return digital asset • Unlock service • Provide receipt
            </p>
            <p className="font-sentient text-xl mt-2 text-primary">Everything is automated.</p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

