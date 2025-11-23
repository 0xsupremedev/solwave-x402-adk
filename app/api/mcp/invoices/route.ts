import { createMcpRouter, jsonError, jsonResponse } from "@/lib/mcp/router";
import { paymentService } from "@/lib/mcp/payment-service";
import { z } from "zod";

const router = createMcpRouter();

const createInvoiceSchema = z.object({
  amount: z.string().min(1),
  token: z.string().optional(),
  metadata: z.record(z.any()).optional(),
  expiresInSeconds: z.number().int().positive().optional(),
});

router.register(
  "GET",
  async ({ query, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const limit = query.get("limit") ? Number(query.get("limit")) : undefined;
    const cursor = query.get("cursor") || undefined;
    const status = query.get("status") || undefined;

    const data = await paymentService.listInvoices({
      merchantId: auth.merchant.id,
      status: status ?? undefined,
      limit,
      cursor,
    });

    return jsonResponse(data);
  },
  { requireAuth: true }
);

router.register(
  "POST",
  async ({ body, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const data = body as z.infer<typeof createInvoiceSchema>;
    const invoice = await paymentService.createInvoice({
      merchantId: auth.merchant.id,
      amount: data.amount,
      token: data.token,
      metadata: data.metadata,
      expiresInSeconds: data.expiresInSeconds,
    });

    return jsonResponse({ invoice }, { status: 201 });
  },
  { schema: createInvoiceSchema }
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

