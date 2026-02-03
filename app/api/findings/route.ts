import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

export async function GET() {
    try {
        const findings = await prisma.finding.findMany({
            orderBy: { updatedAt: 'desc' },
            include: {
                scans: {
                    take: 1,
                    orderBy: { createdAt: 'desc' },
                    select: { target: true }
                }
            }
        });
        return NextResponse.json(findings);
    } catch (error) {
        return NextResponse.json({ error: 'Failed to fetch findings' }, { status: 500 });
    }
}
