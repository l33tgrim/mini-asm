import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { generateVerifyToken } from '@/lib/safety/authorization';
import { audit } from '@/lib/safety/audit';
import { parseTarget } from '@/lib/targets';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

type Context = { params: Promise<{ id: string }> };

const KIND = { domain: 'DOMAIN', ip: 'IP', cidr: 'CIDR' } as const;
const MAX_SCOPE_ENTRIES = 100;

export async function POST(req: Request, { params }: Context) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    const raw = Array.isArray(body.values) ? body.values : [body.values];
    if (raw.length === 0 || raw.length > MAX_SCOPE_ENTRIES) return errorResponse('Provide between 1 and 100 scope values.', 400);

    try {
        const { id: engagementId } = await params;
        const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { id: true, _count: { select: { scope: true } } } });
        if (!engagement) return errorResponse('Engagement not found.', 404);
        if (engagement._count.scope + raw.length > MAX_SCOPE_ENTRIES) return errorResponse('An engagement can hold at most 100 scope entries.', 400);

        // Validate everything first, so one bad value does not leave a half-applied change.
        // The same rules as a scan target apply: no loopback, link-local or reserved space.
        const parsed = raw.map((value) => parseTarget(value));

        const created = [];
        for (const target of parsed) {
            const kind = KIND[target.kind];
            // A new entry always starts unverified, even on an authorised engagement.
            const entry = await prisma.scopeEntry.upsert({
                where: { engagementId_value: { engagementId, value: target.value } },
                update: {},
                create: { engagementId, value: target.value, kind, verifyToken: kind === 'DOMAIN' ? generateVerifyToken() : null, verified: false },
            });
            created.push(entry);
        }
        await audit({ engagementId, action: 'SCOPE_ADDED', detail: parsed.map((p) => p.value).join(', '), actor: 'web' });
        return NextResponse.json(created, { status: 201 });
    } catch (error) {
        return handleError('POST /api/engagements/[id]/scope', error);
    }
}

export async function DELETE(req: Request, { params }: Context) {
    try {
        const { id: engagementId } = await params;
        const entryId = new URL(req.url).searchParams.get('entryId');
        if (!entryId) return errorResponse('entryId is required.', 400);
        // Scoped to this engagement, so an entry id from another engagement cannot be removed here.
        const { count } = await prisma.scopeEntry.deleteMany({ where: { id: entryId, engagementId } });
        if (count === 0) return errorResponse('Scope entry not found.', 404);
        await audit({ engagementId, action: 'SCOPE_REMOVED', detail: entryId, actor: 'web' });
        return NextResponse.json({ ok: true });
    } catch (error) {
        return handleError('DELETE /api/engagements/[id]/scope', error);
    }
}
