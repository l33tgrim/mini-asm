import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { audit } from '@/lib/safety/audit';

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    const body = await req.json().catch(() => ({}));
    const by: string = body.by || 'web-operator';
    const force: boolean = !!body.force;

    const unverifiedDomains = await prisma.scopeEntry.findMany({
        where: { engagementId, kind: 'DOMAIN', verified: false },
    });
    if (unverifiedDomains.length > 0 && !force) {
        return NextResponse.json(
            {
                error: 'unverified_domains',
                detail: `${unverifiedDomains.length} domain(s) are not ownership-verified`,
                domains: unverifiedDomains.map((d) => d.value),
            },
            { status: 409 }
        );
    }

    await prisma.scopeEntry.updateMany({
        where: {
            engagementId,
            OR: [{ kind: 'IP' }, { kind: 'CIDR' }, ...(force ? [{ kind: 'DOMAIN' as const }] : [])],
        },
        data: { verified: true, verifyMethod: 'OPERATOR_ATTESTATION', verifiedAt: new Date() },
    });

    const eng = await prisma.engagement.update({
        where: { id: engagementId },
        data: { status: 'AUTHORIZED', authorizedBy: by, authorizedAt: new Date() },
    });
    await audit({ engagementId, action: 'ENGAGEMENT_AUTHORIZED', detail: `by=${by} force=${force}`, actor: by });
    return NextResponse.json(eng);
}

// Revoke authorization.
export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    const eng = await prisma.engagement.update({
        where: { id: engagementId },
        data: { status: 'REVOKED', revokedAt: new Date() },
    });
    await audit({ engagementId, action: 'ENGAGEMENT_REVOKED', actor: 'web' });
    return NextResponse.json(eng);
}
