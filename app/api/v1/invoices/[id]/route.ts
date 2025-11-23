import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db/client';
import { z } from 'zod';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const invoice = await db.invoice.findUnique({
      where: { id: params.id },
      include: {
        merchant: {
          select: {
            id: true,
            name: true,
            receivingAddress: true,
          },
        },
      },
    });

    if (!invoice) {
      return NextResponse.json(
        { error: 'Invoice not found' },
        { status: 404 }
      );
    }

    // Check if expired
    if (invoice.status === 'PENDING' && invoice.expiresAt < new Date()) {
      await db.invoice.update({
        where: { id: params.id },
        data: { status: 'EXPIRED' },
      });
      invoice.status = 'EXPIRED';
    }

    return NextResponse.json({
      id: invoice.id,
      merchantId: invoice.merchantId,
      merchantName: invoice.merchant.name,
      merchantAddress: invoice.merchant.receivingAddress,
      amount: invoice.amount,
      token: invoice.token,
      status: invoice.status,
      txSignature: invoice.txSignature,
      expiresAt: invoice.expiresAt.toISOString(),
      createdAt: invoice.createdAt.toISOString(),
      updatedAt: invoice.updatedAt.toISOString(),
      metadata: invoice.metadata ? JSON.parse(invoice.metadata) : null,
      nonce: invoice.nonce,
    });
  } catch (error) {
    console.error('Error fetching invoice:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

const updateInvoiceSchema = z.object({
  txSignature: z.string().optional(),
  status: z.enum(['PENDING', 'PAID', 'EXPIRED', 'CANCELLED']).optional(),
});

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const body = await request.json();
    const validated = updateInvoiceSchema.parse(body);
    const { txSignature, status } = validated;

    const invoice = await db.invoice.findUnique({
      where: { id: params.id },
    });

    if (!invoice) {
      return NextResponse.json(
        { error: 'Invoice not found' },
        { status: 404 }
      );
    }

    // Update invoice
    const updated = await db.invoice.update({
      where: { id: params.id },
      data: {
        ...(txSignature && { txSignature }),
        ...(status && { status }),
      },
    });

    // TODO: Trigger webhook if merchant has webhook URL configured

    return NextResponse.json({
      id: updated.id,
      status: updated.status,
      txSignature: updated.txSignature,
      updatedAt: updated.updatedAt.toISOString(),
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error updating invoice:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

