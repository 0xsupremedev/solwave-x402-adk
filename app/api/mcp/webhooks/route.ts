import { createMcpRouter, jsonError, jsonResponse } from "@/lib/mcp/router";
import { merchantService } from "@/lib/mcp/merchant-service";
import { z } from "zod";

const router = createMcpRouter();

const createWebhookSchema = z.object({
  url: z.string().url(),
  events: z.array(z.string()).min(1),
});

const updateWebhookSchema = z.object({
  webhookId: z.string(),
  action: z.enum(["rotate", "deactivate"]),
});

router.register(
  "GET",
  async ({ auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const webhooks = await merchantService.listWebhooks(auth.merchant.id);
    return jsonResponse({ webhooks });
  },
  { requireAuth: true }
);

router.register(
  "POST",
  async ({ body, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const data = body as z.infer<typeof createWebhookSchema>;
    const webhook = await merchantService.registerWebhook(auth.merchant.id, data);
    return jsonResponse({ webhook }, { status: 201 });
  },
  { schema: createWebhookSchema }
);

router.register(
  "PATCH",
  async ({ body, auth }) => {
    if (!auth?.merchant) {
      return jsonError("Merchant context required", 400);
    }

    const data = body as z.infer<typeof updateWebhookSchema>;
    let webhook;

    if (data.action === "rotate") {
      webhook = await merchantService.rotateWebhookSecret(data.webhookId);
    } else {
      webhook = await merchantService.deactivateWebhook(data.webhookId);
    }

    return jsonResponse({ webhook });
  },
  { schema: updateWebhookSchema }
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

export async function PATCH(
  request: Request,
  context: { params?: Record<string, string> }
) {
  return router.handle(request, context);
}

