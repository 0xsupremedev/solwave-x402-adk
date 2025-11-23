"use client";

import { useState, useCallback, useEffect } from "react";
import { PublicKey } from "@solana/web3.js";
import { X402PaymentRequest } from "@/lib/x402/types";
import { PaymentConfirmation } from "./PaymentConfirmation";
import { buildTransaction } from "@/lib/sdk/payments/buildTransaction";
import { submitAndConfirmTransaction, confirmPayment } from "@/lib/sdk/payments/confirmPayment";
import { sendPaymentProof } from "@/lib/sdk/agents/sendPaymentProof";
import { adapterToSigner } from "@/lib/sdk/wallet";
import { Button } from "@/components/ui/button";
import { Wallet, Loader2, CheckCircle, AlertCircle } from "lucide-react";

// Dynamic import helper
function safeRequire(moduleName: string): any {
  if (typeof window === 'undefined') return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(moduleName);
  } catch {
    return null;
  }
}

interface PayWithWalletProps {
  invoice: X402PaymentRequest;
  onSuccess?: (signature: string) => void;
  onError?: (error: Error) => void;
}

export function PayWithWallet({ invoice, onSuccess, onError }: PayWithWalletProps) {
  const [walletHooks, setWalletHooks] = useState<any>(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const walletAdapterReact = safeRequire("@solana/wallet-adapter-react");
      if (walletAdapterReact) {
        setWalletHooks({
          useWallet: walletAdapterReact.useWallet,
          useConnection: walletAdapterReact.useConnection,
        });
      }
    }
  }, []);

  // If wallet adapters are not installed, show error message
  if (!walletHooks) {
    return (
      <div className="p-4 rounded-lg bg-yellow-900/30 border border-yellow-500/50">
        <p className="font-mono text-sm text-yellow-300 mb-2">
          Wallet adapter packages not installed.
        </p>
        <p className="font-mono text-xs text-yellow-400">
          Please install @solana/wallet-adapter-react and related packages. See WALLET_SETUP.md for instructions.
        </p>
      </div>
    );
  }

  const { useWallet, useConnection } = walletHooks;
  const { publicKey, signTransaction, connected } = useWallet();
  const { connection } = useConnection();
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txSignature, setTxSignature] = useState<string | null>(null);

  const handlePay = useCallback(async () => {
    if (!connected || !publicKey || !signTransaction) {
      setError("Please connect your wallet first");
      return;
    }

    setShowConfirmation(true);
  }, [connected, publicKey, signTransaction]);

  const handleConfirm = useCallback(async () => {
    if (!publicKey || !signTransaction) {
      setError("Wallet not connected");
      return;
    }

    setIsProcessing(true);
    setError(null);

    try {
      // Build transaction
      const { transaction } = await buildTransaction({
        invoice,
        payer: publicKey,
        connection,
      });

      // Sign transaction
      const signedTx = await signTransaction(transaction);

      // Submit and confirm
      const signature = await submitAndConfirmTransaction(signedTx, connection);

      // Wait for confirmation
      const confirmation = await confirmPayment({
        signature,
        connection,
      });

      if (!confirmation.confirmed) {
        throw new Error(confirmation.error || "Transaction confirmation failed");
      }

      // Send payment proof to agent
      await sendPaymentProof({
        invoiceId: invoice.invoiceId,
        signature,
        payer: publicKey.toBase58(),
        amount: invoice.amount,
        token: invoice.token,
        confirmed: true,
        confirmedAt: new Date().toISOString(),
        blockTime: confirmation.blockTime,
        slot: confirmation.slot,
      });

      setTxSignature(signature);
      setShowConfirmation(false);
      onSuccess?.(signature);
    } catch (err: any) {
      const errorMessage = err.message || "Payment failed";
      setError(errorMessage);
      onError?.(err);
    } finally {
      setIsProcessing(false);
    }
  }, [publicKey, signTransaction, invoice, connection, onSuccess, onError]);

  if (txSignature) {
    return (
      <div className="p-4 rounded-lg bg-green-900/30 border border-green-500/50 flex items-center gap-3">
        <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
        <div className="flex-1">
          <p className="font-mono text-sm text-green-300 mb-1">Payment confirmed!</p>
          <a
            href={`https://solscan.io/tx/${txSignature}?cluster=${process.env.NEXT_PUBLIC_SOLANA_NETWORK || "mainnet-beta"}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-green-400 hover:text-green-300 underline break-all"
          >
            View on Solscan: {txSignature.slice(0, 8)}...{txSignature.slice(-8)}
          </a>
        </div>
      </div>
    );
  }

  if (!connected) {
    return (
      <div className="p-4 rounded-lg bg-blue-900/30 border border-blue-500/50">
        <p className="font-mono text-sm text-blue-300 mb-3">
          Connect your wallet to pay
        </p>
        <Button
          onClick={() => {
            // This will be handled by WalletButton component
            setError("Please connect your wallet using the wallet button");
          }}
          className="rounded-full border-blue-500/50 bg-blue-900/50 text-blue-200 hover:bg-blue-800/50"
        >
          <Wallet className="w-4 h-4 mr-2" />
          Connect Wallet
        </Button>
      </div>
    );
  }

  return (
    <>
      <Button
        onClick={handlePay}
        disabled={isProcessing}
        className="rounded-full border-blue-500/50 bg-blue-900/50 text-blue-200 hover:bg-blue-800/50"
      >
        {isProcessing ? (
          <>
            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            Processing...
          </>
        ) : (
          <>
            <Wallet className="w-4 h-4 mr-2" />
            Pay {invoice.amount} {invoice.token}
          </>
        )}
      </Button>

      {error && (
        <div className="mt-3 p-3 rounded-lg bg-red-900/30 border border-red-500/50 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400" />
          <span className="font-mono text-xs text-red-300">{error}</span>
        </div>
      )}

      <PaymentConfirmation
        open={showConfirmation}
        onClose={() => {
          if (!isProcessing) {
            setShowConfirmation(false);
          }
        }}
        onConfirm={handleConfirm}
        invoice={invoice}
        isLoading={isProcessing}
        error={error || undefined}
      />
    </>
  );
}

