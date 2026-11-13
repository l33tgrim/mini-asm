import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';

export async function GET() {
    const engagements = await prisma.engagement.findMany({
        orderBy: { createdAt: 'desc' },
        include: { scope: true, _count: { select: { runs: true } } },
    });
    return NextResponse.json(engagements);
}

export async function POST(req: Request) {
    try {
        const { name, description, mode } = await req.json();
        if (!name) return NextResponse.json({ error: 'name is required' }, { status: 400 });
        const eng = await prisma.engagement.create({
            data: {
                name,
                description: description || null,
                mode: mode === 'ACTIVE' ? 'ACTIVE' : 'SAFE',
                status: 'DRAFT',
            },
        });
        await audit({ engagementId: eng.id, action: 'ENGAGEMENT_CREATED', detail: `name=${name} mode=${eng.mode}`, actor: 'web' });
        return NextResponse.json(eng);
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}
