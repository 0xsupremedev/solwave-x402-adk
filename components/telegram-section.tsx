"use client";

import { Bot, MessageSquare, CheckCircle, ExternalLink } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";

export function TelegramSection() {
  return (
    <section id="telegram" className="py-24 container">
      <div className="text-center mb-16">
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-sentient mb-4">
          Your Agents — <i className="font-light">Now on Telegram</i>
        </h2>
        <p className="font-mono text-xs sm:text-sm text-blue-300 text-balance max-w-2xl mx-auto px-4 sm:px-0">
          Deploy your AI agents directly into conversations
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8">
        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Bot className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl font-sentient">Telegram Bot Integration</CardTitle>
            <CardDescription className="font-mono">
              Full-featured bot for autonomous commerce
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 sm:space-y-3 font-mono text-xs sm:text-sm text-foreground/80">
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Place orders directly from Telegram</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Approve/pay invoices inside Telegram</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Receive receipts & explorer links</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Merchant dashboard notifications</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Supports inline buttons & deep links</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Full wallet authentication</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
                <span>Optional custodial flow for low-value items</span>
              </li>
            </ul>
            <div className="flex gap-2 pt-4">
              <Button variant="default" className="flex-1">
                <MessageSquare />
                Try the Demo Bot
              </Button>
              <Button variant="default" className="flex-1">
                <ExternalLink />
                Integrate Webhooks
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MessageSquare className="w-5 h-5" />
              Bot Commands
            </CardTitle>
            <CardDescription className="font-mono">
              Available commands for merchants and users
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 font-mono text-sm">
              <div className="border-l-2 border-primary pl-4">
                <div className="text-primary font-semibold">/start</div>
                <div className="text-foreground/60 mt-1">Authenticate and link wallet</div>
              </div>
              <div className="border-l-2 border-primary pl-4">
                <div className="text-primary font-semibold">/balance</div>
                <div className="text-foreground/60 mt-1">Check your Solana balance</div>
              </div>
              <div className="border-l-2 border-primary pl-4">
                <div className="text-primary font-semibold">/transactions</div>
                <div className="text-foreground/60 mt-1">View transaction history</div>
              </div>
              <div className="border-l-2 border-primary pl-4">
                <div className="text-primary font-semibold">/payouts</div>
                <div className="text-foreground/60 mt-1">Manage merchant payouts</div>
              </div>
              <div className="border-l-2 border-primary pl-4">
                <div className="text-primary font-semibold">/catalog</div>
                <div className="text-foreground/60 mt-1">Browse available items</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

