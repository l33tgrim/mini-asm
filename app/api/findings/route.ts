import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { handleError } from '@/lib/api';

export async function GET() {
    try {
        const findings = await prisma.finding.findMany({ orderBy: { updatedAt: 'desc' } });
        return NextResponse.json(findings);
    } catch (error) {
        return handleError('GET /api/findings', error);
    }
}
