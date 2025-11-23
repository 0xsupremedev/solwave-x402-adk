"use client";

import { useState } from "react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Zap, ExternalLink, Loader2, CheckCircle } from "lucide-react";

export function TestPaymentButton() {
  const [isProcessing, setIsProcessing] = useState(false);
  const [invoiceId, setInvoiceId] = useState<string | null>(null);
  const [txSignature, setTxSignature] = useState<string | null>(null);

  const handleTestPayment = async () => {
    setIsProcessing(true);
    // Simulate payment creation and processing
    setTimeout(() => {
      const mockInvoiceId = `INV-${Date.now()}`;
      const mockTxSig = "5j7s8K9L2mN3pQ4rT5vW6xY7zA8bC9dE0fG1hI2jK3lM4nO5p";
      setInvoiceId(mockInvoiceId);
      setTxSignature(mockTxSig);
      setIsProcessing(false);
    }, 2000);
  };

  return (
    <Card className="border-border bg-background/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="w-5 h-5" />
          Test x402 Payment
        </CardTitle>
        <CardDescription className="font-mono">
          Create a sandbox test payment on devnet
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button
          variant="default"
          className="w-full"
          onClick={handleTestPayment}
          disabled={isProcessing}
        >
          {isProcessing ? (
            <>
              <Loader2 className="animate-spin" />
              Processing...
            </>
          ) : (
            <>
              <Zap />
              Run Test Payment
            </>
          )}
        </Button>

        {invoiceId && (
          <div className="border border-border rounded-lg p-4 space-y-3 bg-background/30">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-primary" />
              <span className="text-sm font-mono text-foreground/80">Payment Created</span>
            </div>
            <div>
              <div className="text-xs font-mono text-foreground/60 mb-1">Invoice ID</div>
              <div className="text-sm font-mono text-foreground/80">{invoiceId}</div>
            </div>
            {txSignature && (
              <div>
                <div className="text-xs font-mono text-foreground/60 mb-1">Transaction</div>
                <div className="text-sm font-mono text-foreground/80 break-all mb-2">
                  {txSignature}
                </div>
                <a
                  href={`https://explorer.solana.com/tx/${txSignature}?cluster=devnet`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-sm font-mono text-primary hover:text-primary/80 transition-colors"
                >
                  View on Explorer
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

