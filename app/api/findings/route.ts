import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { handleError } from '@/lib/api';

// Closed ports are left out unless ?closed=1 asks for them, and false positives
// unless ?dismissed=1 does.
export async function GET(req: Request) {
    try {
        const params = new URL(req.url).searchParams;
        const withClosed = params.get('closed') === '1';
        const withDismissed = params.get('dismissed') === '1';
        const findings = await prisma.finding.findMany({
            where: { ...(withClosed ? {} : { closedAt: null }), ...(withDismissed ? {} : { dismissedAt: null }) },
            orderBy: { updatedAt: 'desc' },
        });
        return NextResponse.json(findings);
    } catch (error) {
        return handleError('GET /api/findings', error);
    }
}
