/**
 * Payment Flow Adapter
 * Bridges between ADK agent and wallet UI
 * Detects agent-generated invoices and triggers payment UI
 */

import { PaymentPayload, PaymentRequirements, X402PaymentRequiredResponse } from "../extensions/types";
import { X402PaymentRequest } from "@/lib/x402/types";
import { paymentRequirementsToX402Invoice } from "../x402-tools/invoice-tools";

/**
 * Payment Flow Event Types
 */
export type PaymentFlowEvent =
  | { type: "INVOICE_CREATED"; invoice: X402PaymentRequest }
  | { type: "PAYMENT_SUBMITTED"; payload: PaymentPayload }
  | { type: "PAYMENT_CONFIRMED"; signature: string; invoiceId: string }
  | { type: "PAYMENT_FAILED"; error: string; invoiceId?: string };

/**
 * Payment Flow Callback
 */
export type PaymentFlowCallback = (event: PaymentFlowEvent) => void | Promise<void>;

/**
 * Payment Flow Adapter
 * Manages the flow between agent and wallet UI
 */
export class PaymentFlowAdapter {
  private callbacks: Set<PaymentFlowCallback> = new Set();
  private pendingInvoices: Map<string, X402PaymentRequest> = new Map();

  /**
   * Register a callback for payment flow events
   */
  onEvent(callback: PaymentFlowCallback): () => void {
    this.callbacks.add(callback);
    return () => this.callbacks.delete(callback);
  }

  /**
   * Emit a payment flow event
   */
  private async emitEvent(event: PaymentFlowEvent): Promise<void> {
    await Promise.all(
      Array.from(this.callbacks).map(async (callback) => {
        try {
          await callback(event);
        } catch (error) {
          console.error("Payment flow callback error:", error);
        }
      })
    );
  }

  /**
   * Handle payment requirements from agent
   * Converts to x402 invoice and triggers payment UI
   */
  async handlePaymentRequired(
    requirements: X402PaymentRequiredResponse,
    merchantId: string
  ): Promise<X402PaymentRequest> {
    // Convert first requirement to invoice (for now, support single payment)
    const requirement = requirements.requirements[0];
    if (!requirement) {
      throw new Error("No payment requirements provided");
    }

    // Convert to x402 invoice
    const invoice = await paymentRequirementsToX402Invoice(requirement, merchantId);

    // Store pending invoice
    this.pendingInvoices.set(invoice.invoiceId, invoice);

    // Emit invoice created event
    await this.emitEvent({
      type: "INVOICE_CREATED",
      invoice,
    });

    return invoice;
  }

  /**
   * Handle payment submission
   * Called when user submits payment via wallet
   */
  async handlePaymentSubmitted(payload: PaymentPayload): Promise<void> {
    await this.emitEvent({
      type: "PAYMENT_SUBMITTED",
      payload,
    });
  }

  /**
   * Handle payment confirmation
   * Called when payment is confirmed on-chain
   */
  async handlePaymentConfirmed(signature: string, invoiceId: string): Promise<void> {
    // Remove from pending invoices
    this.pendingInvoices.delete(invoiceId);

    await this.emitEvent({
      type: "PAYMENT_CONFIRMED",
      signature,
      invoiceId,
    });
  }

  /**
   * Handle payment failure
   */
  async handlePaymentFailed(error: string, invoiceId?: string): Promise<void> {
    if (invoiceId) {
      this.pendingInvoices.delete(invoiceId);
    }

    await this.emitEvent({
      type: "PAYMENT_FAILED",
      error,
      invoiceId,
    });
  }

  /**
   * Get pending invoice
   */
  getPendingInvoice(invoiceId: string): X402PaymentRequest | undefined {
    return this.pendingInvoices.get(invoiceId);
  }

  /**
   * Get all pending invoices
   */
  getPendingInvoices(): X402PaymentRequest[] {
    return Array.from(this.pendingInvoices.values());
  }

  /**
   * Clear pending invoice
   */
  clearPendingInvoice(invoiceId: string): void {
    this.pendingInvoices.delete(invoiceId);
  }
}

/**
 * Global payment flow adapter instance
 */
let paymentFlowAdapterInstance: PaymentFlowAdapter | null = null;

/**
 * Get or create payment flow adapter instance
 */
export function getPaymentFlowAdapter(): PaymentFlowAdapter {
  if (!paymentFlowAdapterInstance) {
    paymentFlowAdapterInstance = new PaymentFlowAdapter();
  }
  return paymentFlowAdapterInstance;
}

