import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';
import { errorResponse, handleError } from '@/lib/api';

type Context = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Context) {
    try {
        const { id } = await params;
        const eng = await prisma.engagement.findUnique({
            where: { id },
            include: {
                scope: true,
                runs: {
                    orderBy: { createdAt: 'desc' },
                    take: 100,
                    include: { results: { orderBy: { createdAt: 'asc' } } },
                },
                auditLogs: { orderBy: { createdAt: 'desc' }, take: 50 },
            },
        });
        if (!eng) return errorResponse('Engagement not found.', 404);
        return NextResponse.json(eng);
    } catch (error) {
        return handleError('GET /api/engagements/[id]', error);
    }
}

export async function DELETE(_req: Request, { params }: Context) {
    try {
        const { id } = await params;
        const { count } = await prisma.engagement.deleteMany({ where: { id } });
        if (count === 0) return errorResponse('Engagement not found.', 404);
        await audit({ action: 'ENGAGEMENT_DELETED', detail: id, actor: 'web' });
        return NextResponse.json({ ok: true });
    } catch (error) {
        return handleError('DELETE /api/engagements/[id]', error);
    }
}
