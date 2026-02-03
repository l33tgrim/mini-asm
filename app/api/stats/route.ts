import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

export async function GET() {
    try {
        const findings = await prisma.finding.groupBy({
            by: ['severity'],
            _count: {
                severity: true,
            },
        });

        const severityMap: Record<string, number> = {
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
        };

        findings.forEach((f) => {
            severityMap[f.severity] = f._count.severity;
        });

        const stats = [
            { name: 'Critical', value: severityMap.CRITICAL, color: '#ef4444' },
            { name: 'High', value: severityMap.HIGH, color: '#f97316' },
            { name: 'Medium', value: severityMap.MEDIUM, color: '#eab308' },
            { name: 'Low', value: severityMap.LOW, color: '#3b82f6' },
        ];

        return NextResponse.json(stats);
    } catch (error) {
        return NextResponse.json({ error: 'Failed to fetch stats' }, { status: 500 });
    }
}
