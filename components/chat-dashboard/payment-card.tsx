import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PayWithWallet } from "@/components/flows/PayWithWallet";
import type { PaymentChatMessage, PaymentStatus } from "./chat-types";
import { cn } from "@/lib/utils";

interface PaymentCardProps {
  message: PaymentChatMessage;
  onStatusChange: (invoiceId: string, status: PaymentStatus) => void;
  onSuccess: (invoiceId: string, signature: string) => void;
  onError: (invoiceId: string, message: string) => void;
}

const STATUS_COPY: Record<PaymentStatus, { label: string; className: string }> = {
  pending: { label: "Pending", className: "bg-blue-500/10 text-blue-200 border-blue-500/30" },
  submitted: { label: "Submitted", className: "bg-yellow-500/10 text-yellow-200 border-yellow-500/30" },
  confirmed: { label: "Confirmed", className: "bg-green-500/10 text-green-200 border-green-500/30" },
  failed: { label: "Failed", className: "bg-red-500/10 text-red-200 border-red-500/30" },
};

export function PaymentCard({
  message,
  onStatusChange,
  onSuccess,
  onError,
}: PaymentCardProps) {
  const { invoice, status, signature } = message.payment;
  const statusMeta = STATUS_COPY[status];

  return (
    <Card className="bg-blue-950/40 border border-blue-500/30 rounded-2xl p-4 space-y-4 shadow-lg shadow-blue-900/30">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-sentient text-blue-100 text-lg">
            {invoice.amount} <span className="text-blue-300">{invoice.token}</span>
          </p>
          <p className="font-mono text-xs text-blue-400/80 mt-1">
            Invoice #{invoice.invoiceId}
          </p>
        </div>
        <Badge className={cn("font-mono text-xs border", statusMeta.className)}>
          {statusMeta.label}
        </Badge>
      </div>

      <div className="grid gap-3 text-sm font-mono text-blue-200">
        <div className="flex justify-between">
          <span className="text-blue-400/70">Recipient</span>
          <span className="text-right w-44 truncate">{invoice.recipient}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-blue-400/70">Expires</span>
          <span>{new Date(invoice.expiresAt).toLocaleTimeString()}</span>
        </div>
      </div>

      {status === "confirmed" && signature ? (
        <div className="rounded-xl bg-green-900/20 border border-green-500/30 p-3">
          <p className="font-mono text-xs text-green-200 mb-1">Payment confirmed</p>
          <a
            href={`https://solscan.io/tx/${signature}?cluster=${process.env.NEXT_PUBLIC_SOLANA_NETWORK || "mainnet-beta"}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-green-300 underline break-all"
          >
            {signature}
          </a>
        </div>
      ) : status === "failed" ? (
        <div className="rounded-xl bg-red-900/20 border border-red-500/30 p-3 font-mono text-xs text-red-200">
          Payment failed. Please try again.
        </div>
      ) : (
        <PayWithWallet
          invoice={invoice}
          onSuccess={(sig) => onSuccess(invoice.invoiceId, sig)}
          onError={(err) => {
            onStatusChange(invoice.invoiceId, "failed");
            onError(invoice.invoiceId, err.message || "Payment error");
          }}
        />
      )}
    </Card>
  );
}

