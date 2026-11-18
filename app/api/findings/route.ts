import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { handleError } from '@/lib/api';

// Closed ports are left out unless ?closed=1 asks for them.
export async function GET(req: Request) {
    try {
        const withClosed = new URL(req.url).searchParams.get('closed') === '1';
        const findings = await prisma.finding.findMany({
            where: withClosed ? undefined : { closedAt: null },
            orderBy: { updatedAt: 'desc' },
        });
        return NextResponse.json(findings);
    } catch (error) {
        return handleError('GET /api/findings', error);
    }
}
