"use client";

import Link from "next/link";
import { GL } from "./gl";
import { Pill } from "./pill";
import { Button } from "./ui/button";
import { useState } from "react";
import { ArrowRight, BookOpen, Bot } from "lucide-react";

export function Hero() {
  const [hovering, setHovering] = useState(false);
  return (
    <div className="flex flex-col h-svh justify-between">
      <GL hovering={hovering} />

      <div className="pb-16 mt-auto text-center relative">
        <Pill className="mb-6">x402 Solana Integration Active</Pill>
        <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-sentient leading-tight">
          Welcome to x402 on Solana <br />
          <i className="font-light">AI-Powered Payments for the Autonomous Web</i>
        </h1>
        <p className="font-mono text-xs sm:text-sm md:text-base text-blue-300 text-balance mt-6 sm:mt-8 max-w-[640px] mx-auto px-4 sm:px-0">
          Experience real on-chain payments, autonomous agents, and decentralized commerce — all powered by Solana, x402, MCP tools, and the Google ADK. Build, test, and deploy AI agents that can transact, charge, and verify payments — automatically.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 mt-14">
          <Link className="contents max-sm:hidden" href="/#demo">
            <Button
              onMouseEnter={() => setHovering(true)}
              onMouseLeave={() => setHovering(false)}
            >
              <ArrowRight />
              Start Building
            </Button>
          </Link>
          <Link className="contents max-sm:hidden" href="/docs">
            <Button
              variant="default"
              onMouseEnter={() => setHovering(true)}
              onMouseLeave={() => setHovering(false)}
            >
              <BookOpen />
              Explore Documentation
            </Button>
          </Link>
          <Link className="contents max-sm:hidden" href="/#telegram">
            <Button
              variant="default"
              onMouseEnter={() => setHovering(true)}
              onMouseLeave={() => setHovering(false)}
            >
              <Bot />
              Launch Telegram Bot
            </Button>
          </Link>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-4 mt-4 sm:hidden">
          <Link className="contents" href="/#demo">
            <Button
              size="sm"
              onMouseEnter={() => setHovering(true)}
              onMouseLeave={() => setHovering(false)}
            >
              Start Building
            </Button>
          </Link>
          <Link className="contents" href="/docs">
            <Button
              size="sm"
              variant="default"
              onMouseEnter={() => setHovering(true)}
              onMouseLeave={() => setHovering(false)}
            >
              Docs
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
