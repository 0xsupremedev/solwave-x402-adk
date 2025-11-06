'use client';

import { useState } from 'react';
import { Card } from '../ui/Card';
import { formatPaymentAmount, formatAddress } from '@/lib/solana';
import { PaymentButton } from './PaymentButton';
import type { PaymentRequirements } from '../../types/x402';
import Link from 'next/link';

interface ResourceCardProps {
  route: string;
  requirements: PaymentRequirements;
  baseUrl?: string;
}

export function ResourceCard({ route, requirements, baseUrl = 'http://localhost:8080' }: ResourceCardProps) {
  const paymentInfo = formatPaymentAmount(
    requirements.maxAmountRequired,
    requirements.asset,
    (requirements.extra as any)?.name as string | undefined
  );

  // Extract method and path from route (format: "GET /api/data" or "/api/data")
  const routeParts = route.split(' ');
  const method = routeParts.length > 1 ? routeParts[0] : 'GET';
  const path = routeParts.length > 1 ? routeParts[1] : routeParts[0];
  const resourceUrl = `${baseUrl}${path}`;

  return (
    <Card className="transition p-6 hover:shadow-xl hover:shadow-brand/10 transform hover:-translate-y-0.5">
      <div className="space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-brand/15 text-brand font-semibold border border-brand/30">{method}</span>
            <Link 
              href={`/resources/${encodeURIComponent(route)}`}
              className="text-sm text-neutral-300 hover:text-white transition-colors font-mono"
            >
              {path}
            </Link>
          </div>
          <h3 className="text-lg font-semibold text-white leading-snug">{requirements.description ?? 'Paid endpoint'}</h3>
        </div>

        <div className="flex items-center justify-between">
          <div className="text-xl md:text-2xl font-bold text-brand">{paymentInfo.display}</div>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs text-neutral-400">
          <div>
            <span className="text-neutral-500">Network:</span> {requirements.network.replace('solana-', '')}
          </div>
          <div>
            <span className="text-neutral-500">Asset:</span> {String((requirements.extra as any)?.name || 'Native')}
          </div>
        </div>

        <div className="pt-3 border-t border-white/10">
          <PaymentButton
            resourceUrl={resourceUrl}
            requirements={requirements}
            className="w-full px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors"
          >
            Pay & Access
          </PaymentButton>
        </div>
      </div>
    </Card>
  );
}

