import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { verifyDomainOwnership } from '@/lib/safety/authorization';
import { audit } from '@/lib/safety/audit';

export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    const entries = await prisma.scopeEntry.findMany({ where: { engagementId, kind: 'DOMAIN' } });
    const report = [];
    for (const e of entries) {
        if (!e.verifyToken) continue;
        const res = await verifyDomainOwnership(e.value, e.verifyToken);
        if (res.verified) {
            await prisma.scopeEntry.update({
                where: { id: e.id },
                data: { verified: true, verifyMethod: res.method, verifiedAt: new Date() },
            });
        }
        await audit({
            engagementId,
            action: res.verified ? 'OWNERSHIP_VERIFIED' : 'OWNERSHIP_FAILED',
            target: e.value,
            detail: res.detail,
            actor: 'web',
        });
        report.push({ id: e.id, value: e.value, ...res });
    }
    return NextResponse.json(report);
}
