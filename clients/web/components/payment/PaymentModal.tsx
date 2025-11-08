'use client';

import { useState, useEffect } from 'react';
import { useWallet } from '@solana/wallet-adapter-react';
import type { PaymentRequirements } from '../../types/x402';
import { createPaymentHeader, executePayment } from '../../lib/payments';
import { formatPaymentAmount } from '../../lib/solana';
import { getSolscanUrl } from '../../lib/wallet';
import { TransactionStatus } from './TransactionStatus';
import toast from 'react-hot-toast';

interface PaymentModalProps {
  isOpen: boolean;
  onClose: () => void;
  resourceUrl: string;
  requirements: PaymentRequirements;
}

export function PaymentModal({ isOpen, onClose, resourceUrl, requirements }: PaymentModalProps) {
  const { publicKey } = useWallet();
  const [status, setStatus] = useState<'idle' | 'pending' | 'verifying' | 'success' | 'error'>('idle');
  const [txHash, setTxHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [optimistic, setOptimistic] = useState(false);
  const [batchSettlement, setBatchSettlement] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setStatus('idle');
      setTxHash(null);
      setError(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const paymentInfo = formatPaymentAmount(
    requirements.maxAmountRequired,
    requirements.asset,
    requirements.extra?.name as string
  );

  const handlePayment = async () => {
    if (!publicKey) {
      toast.error('Please connect your wallet first');
      return;
    }

    try {
      setStatus('pending');
      setError(null);

      // Create payment header
      const paymentHeader = await createPaymentHeader(publicKey, requirements);

      // Execute payment
      const result = await executePayment(resourceUrl, paymentHeader);

      if (result.success) {
        const settlement = result.settlement;
        
        // Check for optimistic verification
        if (settlement?.optimistic) {
          setOptimistic(true);
          setStatus('verifying');
          toast.success('Payment verified optimistically! Confirming on-chain...');
        } else {
          setStatus('verifying');
        }

        // Check for batch settlement
                if (settlement?.batchSettlement) {
                  setBatchSettlement(true);
                  toast('Payment queued for batch settlement', { icon: 'ℹ️' });
                }

        if (settlement?.txHash) {
          setTxHash(settlement.txHash);
        } else if (settlement?.txHash === 'queued_for_batch') {
          setTxHash(null);
          setBatchSettlement(true);
        }
      } else {
        setError(result.error || 'Payment failed');
        setStatus('error');
        toast.error(result.error || 'Payment failed');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      setStatus('error');
      toast.error(errorMessage);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 rounded-xl shadow-2xl border border-brand/20 max-w-md w-full mx-4 p-6 space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold text-white">Payment Required</h2>
          <button
            onClick={onClose}
            className="text-neutral-400 hover:text-white transition-colors"
            disabled={status === 'pending'}
          >
            ✕
          </button>
        </div>

        <div className="space-y-4">
          <div className="bg-slate-800 rounded-lg p-4 space-y-2">
            <div className="flex justify-between">
              <span className="text-neutral-400">Resource:</span>
              <span className="text-white font-mono text-sm">{requirements.resource}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-400">Amount:</span>
              <span className="text-brand font-semibold">{paymentInfo.display}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-400">Network:</span>
              <span className="text-white">{requirements.network}</span>
            </div>
            {requirements.description && (
              <div className="pt-2 border-t border-slate-700">
                <p className="text-neutral-300 text-sm">{requirements.description}</p>
              </div>
            )}
          </div>

          {status === 'idle' && (
            <button
              onClick={handlePayment}
              disabled={!publicKey}
              className="w-full px-4 py-3 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {!publicKey ? 'Connect Wallet First' : 'Pay Now'}
            </button>
          )}

          {status === 'pending' && (
            <div className="flex items-center justify-center space-x-2 text-brand">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-brand"></div>
              <span>Processing payment...</span>
            </div>
          )}

          {(status === 'verifying' || status === 'success') && (
            <div className="space-y-3">
              {optimistic && (
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                  <p className="text-blue-400 text-sm font-medium">⚡ Optimistic Verification</p>
                  <p className="text-blue-300 text-xs mt-1">Payment verified quickly, confirming on-chain...</p>
                </div>
              )}
              {batchSettlement && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3">
                  <p className="text-purple-400 text-sm font-medium">📦 Batch Settlement</p>
                  <p className="text-purple-300 text-xs mt-1">Payment queued for efficient batch processing</p>
                </div>
              )}
              {txHash && (
                <TransactionStatus
                  signature={txHash}
                  network={requirements.network}
                  onConfirmed={() => {
                    setStatus('success');
                    toast.success('Transaction confirmed on-chain!');
                  }}
                  onFailed={() => {
                    setStatus('error');
                    setError('Transaction failed to confirm');
                  }}
                />
              )}
              {status === 'success' && (
                <button
                  onClick={onClose}
                  className="w-full px-4 py-3 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors"
                >
                  Close
                </button>
              )}
            </div>
          )}

          {status === 'error' && (
            <div className="space-y-3">
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                <p className="text-red-400 font-semibold">Payment Failed</p>
                {error && <p className="text-red-300 text-sm mt-1">{error}</p>}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handlePayment}
                  className="flex-1 px-4 py-3 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors"
                >
                  Retry
                </button>
                <button
                  onClick={onClose}
                  className="flex-1 px-4 py-3 rounded-lg bg-slate-700 hover:bg-slate-600 text-white font-medium transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
