"use client";

import { Coins, CheckCircle, ExternalLink } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { PayWithWallet } from "@/components/flows/PayWithWallet";
import { X402PaymentRequest } from "@/lib/x402/types";

interface PaymentMessageProps {
  invoiceId: string;
  amount: string;
  token: string;
  status: string;
  recipient?: string;
  expiresAt?: string;
  nonce?: string;
  metadata?: Record<string, any>;
}

export function PaymentMessage({ 
  invoiceId, 
  amount, 
  token, 
  status,
  recipient,
  expiresAt,
  nonce,
  metadata
}: PaymentMessageProps) {
  const isPaid = status === "paid" || status === "settled";

  // Build x402 payment request if we have all required fields
  const paymentRequest: X402PaymentRequest | null = recipient && expiresAt && nonce
    ? {
        invoiceId,
        amount,
        token,
        recipient,
        nonce,
        expiresAt,
        metadata,
      }
    : null;

  return (
    <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
      <CardContent className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Coins className="w-4 h-4 text-blue-400" />
          <span className="font-mono text-sm font-semibold text-blue-200">Payment Request</span>
        </div>
        <div className="space-y-2 font-mono text-sm">
          <div className="flex justify-between">
            <span className="text-blue-300/60">Invoice ID:</span>
            <span className="text-blue-200">{invoiceId}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-blue-300/60">Amount:</span>
            <span className="text-blue-400 font-semibold">{amount} {token}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-blue-300/60">Status:</span>
            <span className={`${isPaid ? "text-green-400" : "text-blue-300/60"}`}>
              {isPaid ? "Paid" : "Pending"}
            </span>
          </div>
          {recipient && (
            <div className="flex justify-between">
              <span className="text-blue-300/60">Recipient:</span>
              <span className="text-blue-200 text-xs break-all">{recipient.slice(0, 8)}...{recipient.slice(-8)}</span>
            </div>
          )}
        </div>
        {!isPaid && paymentRequest && (
          <div className="pt-2 border-t border-blue-500/30">
            <PayWithWallet
              invoice={paymentRequest}
              onSuccess={(signature) => {
                console.log("Payment successful:", signature);
              }}
              onError={(error) => {
                console.error("Payment error:", error);
              }}
            />
          </div>
        )}
        {isPaid && (
          <div className="pt-2 border-t border-blue-500/30 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-green-400" />
            <span className="font-mono text-xs text-green-300">Payment confirmed</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

