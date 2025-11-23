import { db } from "@/lib/db/client";
import { createX402Invoice, getX402Invoice } from "@/lib/x402/invoice";
import type { X402Invoice } from "@/lib/x402/types";
import crypto from "crypto";
import { verifyPaymentReceipt, pollTransactionConfirmation } from "@/lib/solana/verification";

export interface CreateInvoiceInput {
  merchantId: string;
  amount: string;
  token?: string;
  metadata?: Record<string, unknown>;
  expiresInSeconds?: number;
}

export interface RecordPaymentInput {
  invoiceId: string;
  signature: string;
  payer?: string;
  amountLamports?: number;
}

export interface InvoiceFilter {
  merchantId?: string;
  status?: string;
  limit?: number;
  cursor?: string;
}

export class PaymentService {
  async createInvoice(input: CreateInvoiceInput): Promise<X402Invoice> {
    return createX402Invoice(
      input.merchantId,
      input.amount,
      input.token ?? "USDC",
      input.metadata,
      input.expiresInSeconds ?? 3600
    );
  }

  async getInvoice(invoiceId: string): Promise<X402Invoice | null> {
    return getX402Invoice(invoiceId);
  }

  async listInvoices(filter: InvoiceFilter = {}) {
    const limit = Math.min(filter.limit ?? 20, 100);

    const invoices = await db.invoice.findMany({
      where: {
        ...(filter.merchantId ? { merchantId: filter.merchantId } : {}),
        ...(filter.status ? { status: filter.status.toUpperCase() as any } : {}),
      },
      take: limit + 1,
      skip: filter.cursor ? 1 : 0,
      ...(filter.cursor
        ? {
            cursor: {
              id: filter.cursor,
            },
          }
        : {}),
      orderBy: {
        createdAt: "desc",
      },
    });

    const nextCursor = invoices.length > limit ? invoices.pop()?.id : undefined;

    return {
      invoices: invoices.map((invoice) => ({
        id: invoice.id,
        merchantId: invoice.merchantId,
        amount: invoice.amount,
        token: invoice.token,
        status: invoice.status.toLowerCase(),
        txSignature: invoice.txSignature ?? undefined,
        expiresAt: invoice.expiresAt.toISOString(),
        createdAt: invoice.createdAt.toISOString(),
        metadata: invoice.metadata ? JSON.parse(invoice.metadata) : undefined,
        nonce: invoice.nonce,
      })),
      nextCursor,
    };
  }

  async recordPayment(input: RecordPaymentInput) {
    const invoice = await db.invoice.findUnique({
      where: { id: input.invoiceId },
      include: {
        merchant: true,
      },
    });

    if (!invoice) {
      throw new Error("Invoice not found");
    }

    if (invoice.status !== "PENDING") {
      throw new Error(`Invoice already ${invoice.status.toLowerCase()}`);
    }

    // Poll confirmation before verifying receipt
    const confirmation = await pollTransactionConfirmation(input.signature);
    if (!confirmation.confirmed) {
      throw new Error(
        confirmation.err instanceof Error
          ? confirmation.err.message
          : "Transaction not confirmed"
      );
    }

    // Optional on-chain validation (best-effort)
    if (invoice.token === "SOL" && input.amountLamports) {
      const verification = await verifyPaymentReceipt(
        input.signature,
        input.amountLamports / 1e9,
        invoice.merchant.receivingAddress
      );

      if (!verification.valid) {
        throw new Error(verification.error || "Payment verification failed");
      }
    }

    const updated = await db.invoice.update({
      where: { id: invoice.id },
      data: {
        status: "PAID",
        txSignature: input.signature,
        updatedAt: new Date(),
      },
    });

    await this.notifyWebhooks(invoice.merchantId, "payment.confirmed", {
      invoiceId: invoice.id,
      signature: input.signature,
      amount: invoice.amount,
      token: invoice.token,
    });

    return updated;
  }

  async cancelInvoice(invoiceId: string) {
    return db.invoice.update({
      where: { id: invoiceId },
      data: {
        status: "CANCELLED",
      },
    });
  }

  async expireInvoices() {
    const expired = await db.invoice.updateMany({
      where: {
        status: "PENDING",
        expiresAt: {
          lt: new Date(),
        },
      },
      data: {
        status: "EXPIRED",
      },
    });

    return expired.count;
  }

  async notifyWebhooks(
    merchantId: string,
    event: string,
    payload: Record<string, unknown>
  ) {
    const webhooks = await db.webhook.findMany({
      where: {
        merchantId,
        active: true,
      },
    });

    if (!webhooks.length) {
      return;
    }

    const body = JSON.stringify({
      event,
      data: payload,
      timestamp: new Date().toISOString(),
    });

    await Promise.all(
      webhooks.map(async (hook) => {
        try {
          const signature = signPayload(body, hook.secret);
          await fetch(hook.url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-webhook-id": hook.id,
              "x-webhook-signature": signature,
            },
            body,
          });
        } catch (error) {
          console.error(
            `[MCP] Failed to deliver webhook ${hook.id} to ${hook.url}:`,
            error
          );
        }
      })
    );
  }
}

function signPayload(body: string, secret: string) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

export const paymentService = new PaymentService();

