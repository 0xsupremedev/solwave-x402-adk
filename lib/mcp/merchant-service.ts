import { db } from "@/lib/db/client";
import type { Merchant, Webhook } from "@prisma/client";
import crypto from "crypto";

export interface MerchantInput {
  userId: string;
  name: string;
  receivingAddress: string;
  webhookUrl?: string;
  supportedToken?: string;
  x402Config?: Record<string, unknown>;
}

export interface UpdateMerchantInput {
  name?: string;
  receivingAddress?: string;
  webhookUrl?: string | null;
  supportedToken?: string;
  x402Config?: Record<string, unknown>;
}

export interface WebhookInput {
  url: string;
  events: string[];
}

export class MerchantService {
  async createMerchant(input: MerchantInput): Promise<Merchant> {
    return db.merchant.create({
      data: {
        userId: input.userId,
        name: input.name,
        receivingAddress: input.receivingAddress,
        webhookUrl: input.webhookUrl,
        supportedToken: input.supportedToken ?? "USDC",
        x402Config: input.x402Config ? JSON.stringify(input.x402Config) : null,
      },
    });
  }

  async getMerchantById(id: string): Promise<Merchant | null> {
    return db.merchant.findUnique({
      where: { id },
    });
  }

  async getMerchantByUserId(userId: string): Promise<Merchant | null> {
    return db.merchant.findUnique({
      where: { userId },
    });
  }

  async listMerchants(limit = 20, cursor?: string) {
    const merchants = await db.merchant.findMany({
      take: limit + 1,
      skip: cursor ? 1 : 0,
      ...(cursor
        ? {
            cursor: {
              id: cursor,
            },
          }
        : {}),
      orderBy: {
        createdAt: "desc",
      },
    });

    const nextCursor = merchants.length > limit ? merchants.pop()?.id : undefined;
    return { merchants, nextCursor };
  }

  async updateMerchant(id: string, input: UpdateMerchantInput): Promise<Merchant> {
    return db.merchant.update({
      where: { id },
      data: {
        ...(input.name ? { name: input.name } : {}),
        ...(input.receivingAddress ? { receivingAddress: input.receivingAddress } : {}),
        ...(input.supportedToken ? { supportedToken: input.supportedToken } : {}),
        webhookUrl: input.webhookUrl ?? undefined,
        x402Config: input.x402Config ? JSON.stringify(input.x402Config) : undefined,
      },
    });
  }

  async registerWebhook(merchantId: string, input: WebhookInput): Promise<Webhook> {
    return db.webhook.create({
      data: {
        merchantId,
        url: input.url,
        secret: generateWebhookSecret(),
        events: JSON.stringify(input.events),
      },
    });
  }

  async listWebhooks(merchantId: string): Promise<Webhook[]> {
    return db.webhook.findMany({
      where: {
        merchantId,
      },
      orderBy: {
        createdAt: "desc",
      },
    });
  }

  async rotateWebhookSecret(webhookId: string): Promise<Webhook> {
    return db.webhook.update({
      where: { id: webhookId },
      data: {
        secret: generateWebhookSecret(),
      },
    });
  }

  async deactivateWebhook(webhookId: string): Promise<Webhook> {
    return db.webhook.update({
      where: { id: webhookId },
      data: {
        active: false,
      },
    });
  }
}

function generateWebhookSecret() {
  return crypto.randomBytes(32).toString("hex");
}

export const merchantService = new MerchantService();

