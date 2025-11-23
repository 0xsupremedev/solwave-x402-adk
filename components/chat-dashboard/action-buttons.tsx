"use client";

import { Button } from "@/components/ui/button";
import { Search, Link2, Dice1, Hand } from "lucide-react";
import { useState } from "react";

export function ActionButtons() {
  const [loading, setLoading] = useState<string | null>(null);

  const handleAction = async (action: string) => {
    setLoading(action);
    // Simulate action
    setTimeout(() => {
      setLoading(null);
    }, 1500);
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4 max-w-4xl mx-auto">
      <Button
        variant="default"
        onClick={() => handleAction("check")}
        disabled={loading === "check"}
        className="text-xs sm:text-sm whitespace-normal h-auto py-3 px-4"
      >
        <Search className="w-4 h-4 flex-shrink-0" />
        <span className="text-center flex-1 break-words">Check Solana account</span>
      </Button>

      <Button
        variant="default"
        onClick={() => handleAction("test")}
        disabled={loading === "test"}
        className="text-xs sm:text-sm whitespace-normal h-auto py-3 px-4"
      >
        <Link2 className="w-4 h-4 flex-shrink-0" />
        <span className="text-center flex-1 break-words">Test x402 payment</span>
      </Button>

      <Button
        variant="default"
        onClick={() => handleAction("random")}
        disabled={loading === "random"}
        className="text-xs sm:text-sm whitespace-normal h-auto py-3 px-4"
      >
        <Dice1 className="w-4 h-4 flex-shrink-0" />
        <span className="text-center flex-1 break-words">Generate random number</span>
      </Button>

      <Button
        variant="default"
        onClick={() => handleAction("hello")}
        disabled={loading === "hello"}
        className="text-xs sm:text-sm whitespace-normal h-auto py-3 px-4"
      >
        <Hand className="w-4 h-4 flex-shrink-0" />
        <span className="text-center flex-1 break-words">Say hello</span>
      </Button>
    </div>
  );
}

