import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';
import { audit } from '@/lib/safety/audit';

const MAX_IDS = 5000;

/**
 * Marks findings as false positives, or restores them with { restore: true }.
 * Dismissed findings are hidden from every list and stay dismissed when a later
 * scan sees the same port again, so a wrong result does not come back each scan.
 */
export async function POST(req: Request) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    const ids = body.ids;
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_IDS || !ids.every((id) => typeof id === 'string' && id.length <= 64)) {
        return errorResponse(`ids must be a list of 1 to ${MAX_IDS} finding ids.`, 400);
    }
    const restore = body.restore === true;
    const reason = typeof body.reason === 'string' ? body.reason.trim().slice(0, 500) : '';

    try {
        const result = await prisma.finding.updateMany({
            where: { id: { in: ids as string[] } },
            data: restore ? { dismissedAt: null, dismissReason: null } : { dismissedAt: new Date(), dismissReason: reason || null },
        });
        const sample = await prisma.finding.findFirst({ where: { id: { in: ids as string[] } }, select: { port: true, protocol: true, service: true } });
        await audit({
            action: restore ? 'FINDINGS_RESTORED' : 'FINDINGS_DISMISSED',
            target: sample ? `${sample.service ?? 'service'} ${sample.port}/${sample.protocol}` : null,
            detail: `${result.count} finding(s)${reason ? `: ${reason}` : ''}`,
            actor: 'web',
        });
        return NextResponse.json({ updated: result.count });
    } catch (error) {
        return handleError('POST /api/findings/dismiss', error);
    }
}
