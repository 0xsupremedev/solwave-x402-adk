import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db/client';
import { z } from 'zod';
import crypto from 'crypto';

const webhookSchema = z.object({
  merchantId: z.string(),
  url: z.string().url(),
  events: z.array(z.string()),
  secret: z.string().optional(),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = webhookSchema.parse(body);

    // Check if merchant exists
    const merchant = await db.merchant.findUnique({
      where: { id: validated.merchantId },
    });

    if (!merchant) {
      return NextResponse.json(
        { error: 'Merchant not found' },
        { status: 404 }
      );
    }

    // Generate secret if not provided
    const secret = validated.secret || crypto.randomBytes(32).toString('hex');

    // Create webhook
    const webhook = await db.webhook.create({
      data: {
        merchantId: validated.merchantId,
        url: validated.url,
        secret,
        events: JSON.stringify(validated.events),
        active: true,
      },
    });

    return NextResponse.json({
      id: webhook.id,
      merchantId: webhook.merchantId,
      url: webhook.url,
      events: JSON.parse(webhook.events),
      active: webhook.active,
      createdAt: webhook.createdAt.toISOString(),
      // Only return secret on creation
      secret,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error registering webhook:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

