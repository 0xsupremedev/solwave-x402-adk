import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db/client';
import { z } from 'zod';

const createInvoiceSchema = z.object({
  merchantId: z.string(),
  amount: z.string(),
  token: z.string().default('USDC'),
  metadata: z.record(z.any()).optional(),
  expiresIn: z.number().optional().default(3600), // 1 hour default
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = createInvoiceSchema.parse(body);

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

    // Generate nonce
    const nonce = `${Date.now()}-${Math.random().toString(36).substring(7)}`;

    // Calculate expiry
    const expiresAt = new Date(Date.now() + validated.expiresIn * 1000);

    // Create invoice
    const invoice = await db.invoice.create({
      data: {
        merchantId: validated.merchantId,
        amount: validated.amount,
        token: validated.token,
        nonce,
        expiresAt,
        metadata: validated.metadata ? JSON.stringify(validated.metadata) : null,
        status: 'PENDING',
      },
    });

    return NextResponse.json({
      id: invoice.id,
      merchantId: invoice.merchantId,
      amount: invoice.amount,
      token: invoice.token,
      status: invoice.status,
      expiresAt: invoice.expiresAt.toISOString(),
      nonce: invoice.nonce,
      metadata: invoice.metadata ? JSON.parse(invoice.metadata) : null,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error creating invoice:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const merchantId = searchParams.get('merchantId');
    const status = searchParams.get('status');
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    const where: {
      merchantId?: string;
      status?: string;
    } = {};
    if (merchantId) where.merchantId = merchantId;
    if (status) where.status = status;

    const invoices = await db.invoice.findMany({
      where,
      take: limit,
      skip: offset,
      orderBy: { createdAt: 'desc' },
      include: {
        merchant: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    return NextResponse.json({
      invoices: invoices.map((inv) => ({
        id: inv.id,
        merchantId: inv.merchantId,
        merchantName: inv.merchant.name,
        amount: inv.amount,
        token: inv.token,
        status: inv.status,
        txSignature: inv.txSignature,
        expiresAt: inv.expiresAt.toISOString(),
        createdAt: inv.createdAt.toISOString(),
        metadata: inv.metadata ? JSON.parse(inv.metadata) : null,
      })),
      total: invoices.length,
    });
  } catch (error) {
    console.error('Error fetching invoices:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

