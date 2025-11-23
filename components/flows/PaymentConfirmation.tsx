"use client";

import { X402PaymentRequest } from "@/lib/x402/types";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Wallet, AlertCircle, CheckCircle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

interface PaymentConfirmationProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  invoice: X402PaymentRequest;
  isLoading?: boolean;
  error?: string;
}

export function PaymentConfirmation({
  open,
  onClose,
  onConfirm,
  invoice,
  isLoading = false,
  error,
}: PaymentConfirmationProps) {
  const isExpired = new Date(invoice.expiresAt).getTime() < Date.now();
  const expiresIn = formatDistanceToNow(new Date(invoice.expiresAt), { addSuffix: true });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="bg-blue-950/95 border-blue-500/50 backdrop-blur-sm max-w-md">
        <DialogHeader>
          <DialogTitle className="text-white font-sentient text-xl">
            Confirm Payment
          </DialogTitle>
          <DialogDescription className="text-blue-300 font-mono text-sm">
            Review payment details before signing
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 mt-4">
          {/* Amount */}
          <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-blue-300">Amount</span>
              <span className="font-sentient text-lg text-white font-semibold">
                {invoice.amount} {invoice.token}
              </span>
            </div>
          </div>

          {/* Recipient */}
          <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
            <div className="flex flex-col gap-2">
              <span className="font-mono text-xs text-blue-300">Recipient</span>
              <span className="font-mono text-sm text-blue-200 break-all">
                {invoice.recipient}
              </span>
            </div>
          </div>

          {/* Invoice ID */}
          <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
            <div className="flex flex-col gap-2">
              <span className="font-mono text-xs text-blue-300">Invoice ID</span>
              <span className="font-mono text-sm text-blue-200 break-all">
                {invoice.invoiceId}
              </span>
            </div>
          </div>

          {/* Expiry */}
          <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-blue-300">Expires</span>
              <span className={`font-mono text-sm ${isExpired ? 'text-red-400' : 'text-blue-200'}`}>
                {isExpired ? "Expired" : expiresIn}
              </span>
            </div>
          </div>

          {/* Network */}
          <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-blue-300">Network</span>
              <span className="font-mono text-sm text-blue-200">
                {process.env.NEXT_PUBLIC_SOLANA_NETWORK || "mainnet-beta"}
              </span>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="p-4 rounded-lg bg-red-900/30 border border-red-500/50 flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-400" />
              <span className="font-mono text-sm text-red-300">{error}</span>
            </div>
          )}

          {/* Expired warning */}
          {isExpired && (
            <div className="p-4 rounded-lg bg-yellow-900/30 border border-yellow-500/50 flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-yellow-400" />
              <span className="font-mono text-sm text-yellow-300">
                This invoice has expired. Please request a new payment.
              </span>
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6">
          <Button
            onClick={onClose}
            variant="outline"
            className="flex-1 rounded-full border-blue-500/50 bg-blue-950/40 text-blue-200 hover:bg-blue-900/50"
            disabled={isLoading}
          >
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            disabled={isLoading || isExpired}
            className="flex-1 rounded-full border-blue-500/50 bg-blue-900/50 text-blue-200 hover:bg-blue-800/50"
          >
            {isLoading ? (
              <>
                <Wallet className="w-4 h-4 mr-2 animate-pulse" />
                Processing...
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4 mr-2" />
                Confirm & Sign
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

