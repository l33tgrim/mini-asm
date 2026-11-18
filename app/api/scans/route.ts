import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { resumeScan, startScan } from '@/lib/scan-runner';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

const scanSummary = {
    id: true,
    target: true,
    status: true,
    type: true,
    currentIndex: true,
    totalIps: true,
    portSpec: true,
    udp: true,
    startedAt: true,
    completedAt: true,
    createdAt: true,
} as const;

export async function GET() {
    try {
        const scans = await prisma.scan.findMany({
            orderBy: { createdAt: 'desc' },
            take: 200,
            select: { ...scanSummary, _count: { select: { findings: { where: { dismissedAt: null } } } } },
        });
        return NextResponse.json(scans);
    } catch (error) {
        return handleError('GET /api/scans', error);
    }
}

export async function POST(req: Request) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);

    try {
        if (body.resumeId !== undefined) {
            if (typeof body.resumeId !== 'string') return errorResponse('resumeId must be a string.', 400);
            const scan = await resumeScan(body.resumeId);
            return NextResponse.json({ id: scan.id });
        }

        if (typeof body.target !== 'string') return errorResponse('Target is required.', 400);
        if (body.ports !== undefined && body.ports !== null && typeof body.ports !== 'string') {
            return errorResponse('ports must be a string such as "default, 8000-8100".', 400);
        }
        if (body.udp !== undefined && typeof body.udp !== 'boolean') return errorResponse('udp must be true or false.', 400);
        const scan = await startScan(body.target, 'MANUAL', { ports: body.ports, udp: body.udp });
        return NextResponse.json({ id: scan.id, target: scan.target, status: scan.status }, { status: 201 });
    } catch (error) {
        return handleError('POST /api/scans', error);
    }
}
