import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

export async function GET() {
    try {
        const engagements = await prisma.engagement.findMany({
            orderBy: { createdAt: 'desc' },
            include: { scope: { select: { id: true, value: true, verified: true } }, _count: { select: { runs: true } } },
        });
        return NextResponse.json(engagements);
    } catch (error) {
        return handleError('GET /api/engagements', error);
    }
}

export async function POST(req: Request) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!name || name.length > 120) return errorResponse('A name of up to 120 characters is required.', 400);
    const description = typeof body.description === 'string' ? body.description.trim().slice(0, 1000) : '';

    try {
        const eng = await prisma.engagement.create({
            data: { name, description: description || null, mode: body.mode === 'ACTIVE' ? 'ACTIVE' : 'SAFE', status: 'DRAFT' },
        });
        await audit({ engagementId: eng.id, action: 'ENGAGEMENT_CREATED', detail: `name=${name} mode=${eng.mode}`, actor: 'web' });
        return NextResponse.json(eng, { status: 201 });
    } catch (error) {
        return handleError('POST /api/engagements', error);
    }
}
