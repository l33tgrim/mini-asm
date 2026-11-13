import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { classifyScope } from '@/lib/safety/scope';
import { generateVerifyToken } from '@/lib/safety/authorization';
import { audit } from '@/lib/safety/audit';

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    const { values } = await req.json();
    const list: string[] = Array.isArray(values) ? values : [values];
    if (list.length === 0) return NextResponse.json({ error: 'values required' }, { status: 400 });

    const created = [];
    for (const raw of list) {
        const value = String(raw).trim().toLowerCase();
        if (!value) continue;
        const kind = classifyScope(value);
        const verifyToken = kind === 'DOMAIN' ? generateVerifyToken() : null;
        const entry = await prisma.scopeEntry.upsert({
            where: { engagementId_value: { engagementId, value } },
            update: {},
            create: { engagementId, value, kind, verifyToken, verified: false },
        });
        created.push(entry);
    }
    await audit({ engagementId, action: 'SCOPE_ADDED', detail: list.join(', '), actor: 'web' });
    return NextResponse.json(created);
}

export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    const { searchParams } = new URL(req.url);
    const entryId = searchParams.get('entryId');
    if (!entryId) return NextResponse.json({ error: 'entryId required' }, { status: 400 });
    await prisma.scopeEntry.delete({ where: { id: entryId } });
    await audit({ engagementId, action: 'SCOPE_REMOVED', detail: entryId, actor: 'web' });
    return NextResponse.json({ ok: true });
}
