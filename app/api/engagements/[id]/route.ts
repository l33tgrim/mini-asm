import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    const eng = await prisma.engagement.findUnique({
        where: { id },
        include: {
            scope: true,
            runs: {
                orderBy: { createdAt: 'desc' },
                include: { results: { orderBy: { createdAt: 'asc' } } },
            },
            auditLogs: { orderBy: { createdAt: 'desc' }, take: 50 },
        },
    });
    if (!eng) return NextResponse.json({ error: 'not found' }, { status: 404 });
    return NextResponse.json(eng);
}

export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    await prisma.engagement.delete({ where: { id } });
    await audit({ action: 'ENGAGEMENT_DELETED', detail: id, actor: 'web' });
    return NextResponse.json({ ok: true });
}
