/**
 * x402 Invoice Tools for A2A Protocol
 * Ported from Python: x402_a2a/src/x402_a2a/core/merchant.py
 * Integrates with existing lib/x402/invoice.ts
 */

import { PaymentRequirements, X402PaymentRequiredResponse, SupportedNetworks } from "../extensions/types";
import { X402PaymentRequest } from "@/lib/x402/types";
import { createX402PaymentRequest } from "@/lib/x402/invoice";

/**
 * Price type - can be string (USD), number, or TokenAmount
 */
export type Price = string | number | TokenAmount;

export interface TokenAmount {
  amount: string;
  currency: string;
  decimals?: number;
}

/**
 * Create Payment Requirements for A2A payment requests
 * Ported from: core/merchant.py create_payment_requirements
 */
export async function createPaymentRequirements(
  price: Price,
  payToAddress: string,
  resource: string,
  network: SupportedNetworks = "solana",
  description: string = "",
  mimeType: string = "application/json",
  scheme: string = "exact",
  maxTimeoutSeconds: number = 600,
  outputSchema?: any,
  extra?: any
): Promise<PaymentRequirements> {
  // Convert price to atomic amount
  // For Solana, we need to handle SOL and SPL tokens
  let maxAmountRequired: string;
  let assetAddress: string;

  if (typeof price === "string") {
    // USD string like "$3.10" - convert to USDC on Solana
    const usdAmount = parseFloat(price.replace("$", ""));
    // For now, assume 1 USD = 1 USDC (6 decimals)
    maxAmountRequired = (usdAmount * 1_000_000).toString();
    assetAddress = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC mint
  } else if (typeof price === "number") {
    // Number - assume SOL (9 decimals)
    maxAmountRequired = (price * 1_000_000_000).toString();
    assetAddress = "So11111111111111111111111111111111111111112"; // SOL mint
  } else {
    // TokenAmount
    const decimals = price.decimals || 9;
    maxAmountRequired = (parseFloat(price.amount) * Math.pow(10, decimals)).toString();
    assetAddress = price.currency; // Should be mint address
  }

  return {
    scheme,
    network,
    asset: assetAddress,
    pay_to: payToAddress,
    max_amount_required: maxAmountRequired,
    resource,
    description,
    mime_type: mimeType,
    max_timeout_seconds: maxTimeoutSeconds,
    output_schema: outputSchema,
    extra: extra || {},
  };
}

/**
 * Convert Payment Requirements to x402 Payment Request
 * Integrates with existing invoice system
 */
export async function paymentRequirementsToX402Invoice(
  requirements: PaymentRequirements,
  merchantId: string
): Promise<X402PaymentRequest> {
  // Create invoice using existing system
  const { createX402Invoice, createX402PaymentRequest: createPaymentRequest } = await import("@/lib/x402/invoice");
  
  const invoice = await createX402Invoice(
    merchantId,
    requirements.max_amount_required,
    requirements.asset,
    requirements.description ? { description: requirements.description } : undefined,
    requirements.max_timeout_seconds || 3600
  );

  // Convert to payment request
  return createPaymentRequest(invoice, requirements.pay_to);
}

/**
 * Create x402 Payment Required Response with multiple options
 */
export async function createX402PaymentRequiredResponse(
  requirements: PaymentRequirements[]
): Promise<X402PaymentRequiredResponse> {
  return {
    requirements,
    message: "Payment required to proceed",
  };
}

/**
 * Create single payment requirement response
 */
export async function createSinglePaymentRequiredResponse(
  price: Price,
  payToAddress: string,
  resource: string,
  network: SupportedNetworks = "solana",
  description?: string
): Promise<X402PaymentRequiredResponse> {
  const requirement = await createPaymentRequirements(
    price,
    payToAddress,
    resource,
    network,
    description
  );

  return createX402PaymentRequiredResponse([requirement]);
}

