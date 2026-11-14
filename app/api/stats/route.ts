import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { handleError } from '@/lib/api';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

// 0.0.0.0 holds the DNS reconnaissance summary, which is not a host finding.
const hostFindings = { ip: { not: '0.0.0.0' } };

export async function GET() {
    try {
        const [bySeverity, hosts, runningScans, totalScans, latest] = await Promise.all([
            prisma.finding.groupBy({ by: ['severity'], where: hostFindings, _count: { _all: true } }),
            prisma.finding.findMany({ where: hostFindings, distinct: ['ip'], select: { ip: true } }),
            prisma.scan.count({ where: { status: 'RUNNING' } }),
            prisma.scan.count(),
            prisma.finding.findFirst({ where: hostFindings, orderBy: { updatedAt: 'desc' }, select: { updatedAt: true } }),
        ]);

        const severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<(typeof SEVERITIES)[number], number>;
        for (const row of bySeverity) {
            if (row.severity in severity) severity[row.severity as keyof typeof severity] = row._count._all;
        }

        return NextResponse.json({
            severity,
            totalFindings: Object.values(severity).reduce((a, b) => a + b, 0),
            assets: hosts.length,
            runningScans,
            totalScans,
            lastDiscovery: latest?.updatedAt ?? null,
        });
    } catch (error) {
        return handleError('GET /api/stats', error);
    }
}
