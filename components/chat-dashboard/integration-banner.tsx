"use client";

import { Pill } from "@/components/pill";

export function IntegrationBanner() {
  return (
    <div className="flex justify-center">
      <Pill className="bg-purple-500/20 border-purple-400/50 text-purple-200">
        <span className="inline-block size-2.5 rounded-full bg-purple-400 mr-2 shadow-glow shadow-purple-400/50" />
        x402 Solana Integration Active
      </Pill>
    </div>
  );
}

