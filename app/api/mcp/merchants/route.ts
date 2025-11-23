import { createMcpRouter, jsonError, jsonResponse } from "@/lib/mcp/router";
import { merchantService } from "@/lib/mcp/merchant-service";
import { z } from "zod";

const router = createMcpRouter();

const createMerchantSchema = z.object({
  userId: z.string().optional(),
  name: z.string().min(2),
  receivingAddress: z.string().min(32),
  webhookUrl: z.string().url().optional(),
  supportedToken: z.string().optional(),
  x402Config: z.record(z.any()).optional(),
});

router.register(
  "GET",
  async ({ query }) => {
    const limit = query.get("limit") ? Number(query.get("limit")) : undefined;
    const cursor = query.get("cursor") || undefined;

    const { merchants, nextCursor } = await merchantService.listMerchants(
      limit,
      cursor
    );

    return jsonResponse({
      merchants,
      nextCursor,
    });
  },
  { requireAuth: true }
);

router.register(
  "POST",
  async ({ body, auth }) => {
    const data = body as z.infer<typeof createMerchantSchema>;
    const userId = data.userId ?? auth?.user.id;

    if (!userId) {
      return jsonError("User ID required", 400);
    }

    const existing = await merchantService.getMerchantByUserId(userId);
    if (existing) {
      return jsonError("Merchant already exists for this user", 409);
    }

    const merchant = await merchantService.createMerchant({
      userId,
      name: data.name,
      receivingAddress: data.receivingAddress,
      webhookUrl: data.webhookUrl,
      supportedToken: data.supportedToken,
      x402Config: data.x402Config,
    });

    return jsonResponse({ merchant }, { status: 201 });
  },
  { schema: createMerchantSchema }
);

export async function GET(request: Request, context: { params?: Record<string, string> }) {
  return router.handle(request, context);
}

export async function POST(
  request: Request,
  context: { params?: Record<string, string> }
) {
  return router.handle(request, context);
}

