import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { errorResponse, handleError } from '@/lib/api';

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    try {
        const { id } = await params;
        const scan = await prisma.scan.findUnique({
            where: { id },
            // ipList and hostMap are internal working data and can be large, so they are left out.
            select: {
                id: true, target: true, status: true, type: true, currentIndex: true, totalIps: true,
                startedAt: true, completedAt: true, createdAt: true, findings: true,
            },
        });
        if (!scan) return errorResponse('Scan not found.', 404);

        scan.findings.sort((a, b) =>
            (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5) ||
            a.ip.localeCompare(b.ip, undefined, { numeric: true }) ||
            a.port - b.port,
        );
        return NextResponse.json(scan);
    } catch (error) {
        return handleError('GET /api/scans/[id]', error);
    }
}
