import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

type Context = { params: Promise<{ id: string }> };

export async function POST(req: Request, { params }: Context) {
    const body = (await readJsonBody(req)) ?? {};
    const by = (typeof body.by === 'string' && body.by.trim().slice(0, 120)) || 'web-operator';
    const force = body.force === true;

    try {
        const { id: engagementId } = await params;
        const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, include: { scope: true } });
        if (!engagement) return errorResponse('Engagement not found.', 404);
        if (engagement.scope.length === 0) return errorResponse('Add at least one scope entry before authorising.', 400);

        const unverified = engagement.scope.filter((s) => s.kind === 'DOMAIN' && !s.verified);
        if (unverified.length > 0 && !force) {
            return NextResponse.json(
                {
                    error: 'unverified_domains',
                    detail: `${unverified.length} domain(s) are not ownership-verified`,
                    domains: unverified.map((d) => d.value),
                },
                { status: 409 },
            );
        }

        // IPs and CIDRs cannot be proven by token, so the operator attests to them.
        // With force, unverified domains are attested the same way. Both are audited.
        await prisma.scopeEntry.updateMany({
            where: { engagementId, verified: false, ...(force ? {} : { kind: { in: ['IP', 'CIDR'] } }) },
            data: { verified: true, verifyMethod: 'OPERATOR_ATTESTATION', verifiedAt: new Date() },
        });

        const eng = await prisma.engagement.update({
            where: { id: engagementId },
            // Clearing revokedAt matters: a re-authorised engagement must actually be usable again.
            data: { status: 'AUTHORIZED', authorizedBy: by, authorizedAt: new Date(), revokedAt: null },
        });
        await audit({
            engagementId,
            action: 'ENGAGEMENT_AUTHORIZED',
            detail: `by=${by} force=${force}${force && unverified.length ? ` attested_domains=${unverified.map((d) => d.value).join(',')}` : ''}`,
            actor: by,
        });
        return NextResponse.json(eng);
    } catch (error) {
        return handleError('POST /api/engagements/[id]/authorize', error);
    }
}

// Revoke authorisation.
export async function DELETE(_req: Request, { params }: Context) {
    try {
        const { id: engagementId } = await params;
        const { count } = await prisma.engagement.updateMany({
            where: { id: engagementId },
            data: { status: 'REVOKED', revokedAt: new Date() },
        });
        if (count === 0) return errorResponse('Engagement not found.', 404);
        await audit({ engagementId, action: 'ENGAGEMENT_REVOKED', actor: 'web' });
        return NextResponse.json({ ok: true });
    } catch (error) {
        return handleError('DELETE /api/engagements/[id]/authorize', error);
    }
}
