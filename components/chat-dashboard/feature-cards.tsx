"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link2, Music, Building2, Square } from "lucide-react";

export function FeatureCards() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6 max-w-4xl mx-auto px-4 sm:px-0">
      {/* Solana Integration Card */}
      <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm shadow-lg shadow-blue-500/20 ring-1 ring-blue-400/20">
        <CardHeader>
          <div className="flex items-start justify-between">
            <CardTitle className="font-sentient text-xl text-white flex items-center gap-2">
              <Link2 className="w-5 h-5 text-blue-400" />
              Solana Integration
            </CardTitle>
            <div className="flex gap-2">
              <Link2 className="w-4 h-4 text-blue-400/60" />
              <Music className="w-4 h-4 text-blue-400/60" />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2 font-mono text-sm text-blue-200">
            <li className="flex items-start gap-2">
              <span className="text-blue-400">•</span>
              <span>Real x402 payments on Solana devnet</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-400">•</span>
              <span>Automatic SOL airdrop</span>
            </li>
          </ul>
        </CardContent>
      </Card>

      {/* AI Tools Card */}
      <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm shadow-lg shadow-blue-500/20 ring-1 ring-blue-400/20">
        <CardHeader>
          <div className="flex items-start justify-between">
            <CardTitle className="font-sentient text-xl text-white flex items-center gap-2">
              <Building2 className="w-5 h-5 text-blue-400" />
              AI Tools
            </CardTitle>
            <div className="flex gap-2">
              <Building2 className="w-4 h-4 text-blue-400/60" />
              <div className="w-4 h-4 border border-blue-400/60 rounded flex items-center justify-center">
                <span className="text-[8px] text-blue-400/60">2</span>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2 font-mono text-sm text-blue-200">
            <li className="flex items-start gap-2">
              <span className="text-blue-400">•</span>
              <span>MCP server with Solana account utilities</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-400">•</span>
              <span>Payment testing tools</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

