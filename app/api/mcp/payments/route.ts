import { createMcpRouter, jsonError, jsonResponse } from "@/lib/mcp/router";
import { paymentService } from "@/lib/mcp/payment-service";
import { z } from "zod";

const router = createMcpRouter();

const recordPaymentSchema = z.object({
  invoiceId: z.string(),
  signature: z.string(),
  payer: z.string().optional(),
  amountLamports: z.number().int().positive().optional(),
});

router.register(
  "GET",
  async ({ query, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const invoiceId = query.get("invoiceId");
    if (!invoiceId) {
      return jsonError("invoiceId query parameter required", 400);
    }

    const invoice = await paymentService.getInvoice(invoiceId);
    if (!invoice || invoice.merchantId !== auth.merchant.id) {
      return jsonError("Invoice not found", 404);
    }

    return jsonResponse({ invoice });
  },
  { requireAuth: true }
);

router.register(
  "POST",
  async ({ body, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const data = body as z.infer<typeof recordPaymentSchema>;
    const invoice = await paymentService.getInvoice(data.invoiceId);

    if (!invoice || invoice.merchantId !== auth.merchant.id) {
      return jsonError("Invoice not found", 404);
    }

    await paymentService.recordPayment({
      invoiceId: data.invoiceId,
      signature: data.signature,
      payer: data.payer,
      amountLamports: data.amountLamports,
    });

    const updated = await paymentService.getInvoice(data.invoiceId);
    return jsonResponse({ invoice: updated });
  },
  { schema: recordPaymentSchema }
);

export async function GET(
  request: Request,
  context: { params?: Record<string, string> }
) {
  return router.handle(request, context);
}

export async function POST(
  request: Request,
  context: { params?: Record<string, string> }
) {
  return router.handle(request, context);
}

