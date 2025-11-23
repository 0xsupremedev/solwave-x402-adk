/**
 * Security Guardrails
 * Implements invoice validation, token validation, double-spend prevention, transaction limits
 */

import { getX402Invoice } from "@/lib/x402/invoice";
import { X402Invoice } from "@/lib/x402/types";
import { PublicKey } from "@solana/web3.js";

export interface GuardrailConfig {
  maxSolPerTransaction?: number;
  maxDailyTransactionLimit?: number;
  approvedMerchants?: string[];
  requireUserConfirmationForLargeAmounts?: boolean;
  largeAmountThreshold?: number;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  warning?: string;
}

/**
 * Guardrails class
 */
export class PaymentGuardrails {
  private config: GuardrailConfig;
  private processedInvoices: Set<string> = new Set();
  private dailyTransactionCounts: Map<string, number> = new Map();
  private dailyTransactionAmounts: Map<string, number> = new Map();

  constructor(config: GuardrailConfig = {}) {
    this.config = {
      maxSolPerTransaction: 100, // Default: 100 SOL
      maxDailyTransactionLimit: 1000, // Default: 1000 transactions per day
      requireUserConfirmationForLargeAmounts: true,
      largeAmountThreshold: 10, // Default: 10 SOL
      ...config,
    };
  }

  /**
   * Validate invoice ID
   */
  async validateInvoiceId(invoiceId: string): Promise<ValidationResult> {
    if (!invoiceId || typeof invoiceId !== "string") {
      return { valid: false, error: "Invalid invoice ID" };
    }

    const invoice = await getX402Invoice(invoiceId);
    if (!invoice) {
      return { valid: false, error: "Invoice not found" };
    }

    return { valid: true };
  }

  /**
   * Validate invoice status
   */
  async validateInvoiceStatus(invoiceId: string): Promise<ValidationResult> {
    const invoice = await getX402Invoice(invoiceId);
    if (!invoice) {
      return { valid: false, error: "Invoice not found" };
    }

    if (invoice.status !== "pending") {
      return {
        valid: false,
        error: `Invoice is ${invoice.status}, cannot process payment`,
      };
    }

    // Check if expired
    const expiresAt = new Date(invoice.expiresAt);
    if (expiresAt < new Date()) {
      return { valid: false, error: "Invoice has expired" };
    }

    return { valid: true };
  }

  /**
   * Validate token
   */
  validateToken(token: string): ValidationResult {
    if (!token || typeof token !== "string") {
      return { valid: false, error: "Invalid token" };
    }

    // Validate Solana address format if it's a mint address
    try {
      new PublicKey(token);
    } catch {
      // If it's not a valid address, check if it's a known token symbol
      const knownTokens = ["SOL", "USDC", "USDT"];
      if (!knownTokens.includes(token.toUpperCase())) {
        return {
          valid: false,
          error: `Unknown token: ${token}`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Prevent double spending
   */
  async preventDoubleSpend(invoiceId: string): Promise<ValidationResult> {
    // Check if invoice has already been processed
    if (this.processedInvoices.has(invoiceId)) {
      return {
        valid: false,
        error: "Invoice has already been processed (double-spend prevention)",
      };
    }

    // Check invoice status in database
    const invoice = await getX402Invoice(invoiceId);
    if (!invoice) {
      return { valid: false, error: "Invoice not found" };
    }

    if (invoice.status === "paid" || invoice.status === "settled") {
      return {
        valid: false,
        error: "Invoice has already been paid",
      };
    }

    // Mark as processed
    this.processedInvoices.add(invoiceId);

    return { valid: true };
  }

  /**
   * Detect expired invoices
   */
  async detectExpiredInvoice(invoiceId: string): Promise<ValidationResult> {
    const invoice = await getX402Invoice(invoiceId);
    if (!invoice) {
      return { valid: false, error: "Invoice not found" };
    }

    const expiresAt = new Date(invoice.expiresAt);
    if (expiresAt < new Date()) {
      return { valid: false, error: "Invoice has expired" };
    }

    return { valid: true };
  }

  /**
   * Enforce transaction limits
   */
  async enforceTransactionLimits(
    amount: number,
    userId?: string
  ): Promise<ValidationResult> {
    // Check max SOL per transaction
    if (this.config.maxSolPerTransaction) {
      if (amount > this.config.maxSolPerTransaction) {
        return {
          valid: false,
          error: `Transaction amount exceeds maximum of ${this.config.maxSolPerTransaction} SOL`,
        };
      }
    }

    // Check daily transaction limits
    if (userId && this.config.maxDailyTransactionLimit) {
      const today = new Date().toISOString().split("T")[0];
      const countKey = `${userId}-${today}`;
      const currentCount = this.dailyTransactionCounts.get(countKey) || 0;

      if (currentCount >= this.config.maxDailyTransactionLimit) {
        return {
          valid: false,
          error: "Daily transaction limit exceeded",
        };
      }
    }

    // Check if user confirmation required for large amounts
    if (
      this.config.requireUserConfirmationForLargeAmounts &&
      this.config.largeAmountThreshold &&
      amount > this.config.largeAmountThreshold
    ) {
      return {
        valid: true,
        warning: `Large amount detected (${amount} SOL). User confirmation required.`,
      };
    }

    return { valid: true };
  }

  /**
   * Check approved merchants
   */
  validateMerchant(merchantId: string): ValidationResult {
    if (
      this.config.approvedMerchants &&
      this.config.approvedMerchants.length > 0
    ) {
      if (!this.config.approvedMerchants.includes(merchantId)) {
        return {
          valid: false,
          error: "Merchant not in approved list",
        };
      }
    }

    return { valid: true };
  }

  /**
   * Record transaction for daily limits
   */
  recordTransaction(userId: string, amount: number): void {
    const today = new Date().toISOString().split("T")[0];
    const countKey = `${userId}-${today}`;
    const amountKey = `${userId}-${today}-amount`;

    const currentCount = this.dailyTransactionCounts.get(countKey) || 0;
    const currentAmount = this.dailyTransactionAmounts.get(amountKey) || 0;

    this.dailyTransactionCounts.set(countKey, currentCount + 1);
    this.dailyTransactionAmounts.set(amountKey, currentAmount + amount);
  }

  /**
   * Comprehensive validation
   */
  async validatePayment(
    invoiceId: string,
    amount: number,
    token: string,
    merchantId: string,
    userId?: string
  ): Promise<ValidationResult> {
    // Validate invoice ID
    const invoiceValidation = await this.validateInvoiceId(invoiceId);
    if (!invoiceValidation.valid) {
      return invoiceValidation;
    }

    // Validate invoice status
    const statusValidation = await this.validateInvoiceStatus(invoiceId);
    if (!statusValidation.valid) {
      return statusValidation;
    }

    // Check for expired invoice
    const expiredValidation = await this.detectExpiredInvoice(invoiceId);
    if (!expiredValidation.valid) {
      return expiredValidation;
    }

    // Prevent double spending
    const doubleSpendValidation = await this.preventDoubleSpend(invoiceId);
    if (!doubleSpendValidation.valid) {
      return doubleSpendValidation;
    }

    // Validate token
    const tokenValidation = this.validateToken(token);
    if (!tokenValidation.valid) {
      return tokenValidation;
    }

    // Validate merchant
    const merchantValidation = this.validateMerchant(merchantId);
    if (!merchantValidation.valid) {
      return merchantValidation;
    }

    // Enforce transaction limits
    const limitValidation = await this.enforceTransactionLimits(amount, userId);
    if (!limitValidation.valid) {
      return limitValidation;
    }

    return { valid: true, warning: limitValidation.warning };
  }

  /**
   * Reset daily counters (call this daily)
   */
  resetDailyCounters(): void {
    this.dailyTransactionCounts.clear();
    this.dailyTransactionAmounts.clear();
  }
}

/**
 * Global guardrails instance
 */
let guardrailsInstance: PaymentGuardrails | null = null;

/**
 * Get or create guardrails instance
 */
export function getGuardrails(config?: GuardrailConfig): PaymentGuardrails {
  if (!guardrailsInstance) {
    guardrailsInstance = new PaymentGuardrails(config);
  }
  return guardrailsInstance;
}

