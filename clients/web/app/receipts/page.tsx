'use client';

import { useState, useEffect } from 'react';
import { getSolscanUrl, getConnection } from '../../lib/wallet';
import { formatPaymentAmount } from '../../lib/solana';
import { format } from 'date-fns';

interface Receipt {
  signature: string;
  timestamp: number;
  resource: string;
  amount: string;
  asset: string;
  network: string;
  status: 'pending' | 'confirmed' | 'failed';
  payer?: string;
}

export default function Receipts() {
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [searchHash, setSearchHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Load receipts from localStorage
    try {
      const stored = localStorage.getItem('microapi_transactions');
      if (stored) {
        const parsed = JSON.parse(stored) as Receipt[];
        setReceipts(parsed);
      }
    } catch (err) {
      console.error('Error loading receipts:', err);
    }
  }, []);

  const handleSearch = async () => {
    if (!searchHash.trim()) {
      setError('Please enter a transaction hash');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Verify transaction exists on Solana
      const connection = getConnection('devnet');
      const signature = await connection.getSignatureStatus(searchHash);
      
      if (!signature.value) {
        setError('Transaction not found');
        setLoading(false);
        return;
      }

      // Get transaction details
      const tx = await connection.getTransaction(searchHash, {
        maxSupportedTransactionVersion: 0,
      });

      if (!tx) {
        setError('Could not fetch transaction details');
        setLoading(false);
        return;
      }

      // Parse transaction for receipt info
      // Safely derive payer from versioned message account keys
      const payerDerived = (() => {
        try {
          const msg: any = tx.transaction.message as any;
          const keys = typeof msg.getAccountKeys === 'function' ? msg.getAccountKeys() : undefined;
          const firstKey = keys?.staticAccountKeys?.[0] || keys?.accountKeys?.[0];
          return typeof firstKey?.toBase58 === 'function' ? firstKey.toBase58() : undefined;
        } catch {
          return undefined;
        }
      })();

      const receipt: Receipt = {
        signature: searchHash,
        timestamp: (tx.blockTime || Date.now() / 1000) * 1000,
        resource: 'Unknown',
        amount: '0',
        asset: 'SOL',
        network: 'solana-devnet',
        status: signature.value.err ? 'failed' : 'confirmed',
        payer: payerDerived,
      };

      setReceipts([receipt, ...receipts]);
      setSearchHash('');
      setLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error fetching transaction');
      setLoading(false);
    }
  };

  return (
    <main className="mx-auto max-w-4xl px-4 py-12 space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">Payment Receipts</h1>
        <p className="text-neutral-400">
          View and verify your x402 payment receipts. Search by transaction hash or view your payment history.
        </p>
      </div>

      {/* Search */}
      <div className="bg-slate-900 rounded-xl p-6 border border-brand/20">
        <h2 className="text-xl font-semibold mb-4">Search Transaction</h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={searchHash}
            onChange={(e) => setSearchHash(e.target.value)}
            placeholder="Enter transaction hash..."
            className="flex-1 px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder-neutral-500 focus:outline-none focus:border-brand"
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button
            onClick={handleSearch}
            disabled={loading}
            className="px-6 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors disabled:opacity-50"
          >
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
      </div>

      {/* Receipts List */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold">Payment History</h2>
        {receipts.length === 0 ? (
          <div className="bg-slate-900 rounded-xl p-8 border border-slate-800 text-center">
            <p className="text-neutral-400">No receipts found. Make a payment to see your history here.</p>
          </div>
        ) : (
          receipts.map((receipt) => {
            const paymentInfo = formatPaymentAmount(receipt.amount, receipt.asset);
            const statusColors = {
              confirmed: 'bg-green-500/10 text-green-400 border-green-500/20',
              pending: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
              failed: 'bg-red-500/10 text-red-400 border-red-500/20',
            };

            return (
              <div
                key={receipt.signature}
                className="bg-slate-900 rounded-xl p-6 border border-slate-800 hover:border-brand/20 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 space-y-3">
                    <div className="flex items-center gap-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-medium border ${statusColors[receipt.status]}`}>
                        {receipt.status.toUpperCase()}
                      </span>
                      <span className="text-neutral-400 text-sm">
                        {format(new Date(receipt.timestamp), 'PPp')}
                      </span>
                    </div>
                    <div>
                      <p className="text-neutral-400 text-sm mb-1">Resource</p>
                      <p className="text-white font-mono text-sm">{receipt.resource}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-neutral-400 text-sm mb-1">Amount</p>
                        <p className="text-brand font-semibold">{paymentInfo.display}</p>
                      </div>
                      <div>
                        <p className="text-neutral-400 text-sm mb-1">Network</p>
                        <p className="text-white">{receipt.network}</p>
                      </div>
                    </div>
                    {receipt.payer && (
                      <div>
                        <p className="text-neutral-400 text-sm mb-1">Payer</p>
                        <p className="text-white font-mono text-sm">{receipt.payer}</p>
                      </div>
                    )}
                  </div>
                  <div className="ml-4">
                    <a
                      href={getSolscanUrl(receipt.signature, receipt.network)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-4 py-2 rounded-lg bg-brand/20 hover:bg-brand/30 text-brand border border-brand/50 transition-colors text-sm font-medium"
                    >
                      View on Solscan →
                    </a>
                  </div>
                </div>
                <div className="mt-4 pt-4 border-t border-slate-800">
                  <p className="text-neutral-400 text-xs font-mono break-all">{receipt.signature}</p>
                </div>
              </div>
            );
          })
        )}
      </div>
    </main>
  );
}
