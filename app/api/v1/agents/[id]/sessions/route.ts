import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db/client';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    const sessions = await db.agentSession.findMany({
      where: { agentId: params.id },
      take: limit,
      skip: offset,
      orderBy: { createdAt: 'desc' },
    });

    return NextResponse.json({
      sessions: sessions.map((session) => ({
        id: session.id,
        agentId: session.agentId,
        traceEvents: session.traceEvents ? JSON.parse(session.traceEvents) : [],
        artifacts: session.artifacts ? JSON.parse(session.artifacts) : [],
        state: session.state ? JSON.parse(session.state) : null,
        createdAt: session.createdAt.toISOString(),
        updatedAt: session.updatedAt.toISOString(),
      })),
      total: sessions.length,
    });
  } catch (error) {
    console.error('Error fetching agent sessions:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const body = await request.json();
    const { traceEvents, artifacts, state } = body;

    const session = await db.agentSession.create({
      data: {
        agentId: params.id,
        traceEvents: traceEvents ? JSON.stringify(traceEvents) : null,
        artifacts: artifacts ? JSON.stringify(artifacts) : null,
        state: state ? JSON.stringify(state) : null,
      },
    });

    return NextResponse.json({
      id: session.id,
      agentId: session.agentId,
      traceEvents: session.traceEvents ? JSON.parse(session.traceEvents) : [],
      artifacts: session.artifacts ? JSON.parse(session.artifacts) : [],
      state: session.state ? JSON.parse(session.state) : null,
      createdAt: session.createdAt.toISOString(),
    });
  } catch (error) {
    console.error('Error creating agent session:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

