import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { errorResponse, handleError } from '@/lib/api';

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

type HostMap = Record<string, string[]>;

function parseHostMap(value: string | null): HostMap {
    if (!value) return {};
    try {
        return JSON.parse(value) as HostMap;
    } catch {
        return {};
    }
}

const hostnames = (map: HostMap) => new Set(Object.values(map).flat());
const MAX_CHANGE_ROWS = 100;

/**
 * Compares a finished scan with the previous finished scan of the same target:
 * which hostnames and open services appeared and which went away. Findings are
 * shared between scans, so a service counts as open in a scan when the finding
 * is linked to it.
 */
async function changesSincePrevious(scan: { id: string; target: string; status: string; createdAt: Date; findings: { ip: string; port: number; service: string | null }[] }) {
    if (scan.status !== 'COMPLETED') return null;

    const previous = await prisma.scan.findFirst({
        where: { target: scan.target, status: 'COMPLETED', createdAt: { lt: scan.createdAt } },
        orderBy: { createdAt: 'desc' },
        select: { id: true, createdAt: true, hostMap: true, findings: { select: { ip: true, port: true, service: true } } },
    });
    if (!previous) return null;

    const current = await prisma.scan.findUnique({ where: { id: scan.id }, select: { hostMap: true } });
    const nowHosts = hostnames(parseHostMap(current?.hostMap ?? null));
    const thenHosts = hostnames(parseHostMap(previous.hostMap));

    const key = (f: { ip: string; port: number }) => `${f.ip}:${f.port}`;
    const real = (f: { port: number }) => f.port !== 0;
    const nowServices = new Map(scan.findings.filter(real).map((f) => [key(f), f]));
    const thenServices = new Map(previous.findings.filter(real).map((f) => [key(f), f]));
    const pickService = (f: { ip: string; port: number; service: string | null }) => ({ ip: f.ip, port: f.port, service: f.service });

    const newServices = [...nowServices.values()].filter((f) => !thenServices.has(key(f))).map(pickService);
    const closedServices = [...thenServices.values()].filter((f) => !nowServices.has(key(f))).map(pickService);
    // Scans from before host tracking have no host map, so host changes cannot be judged against them.
    const comparable = thenHosts.size > 0 && nowHosts.size > 0;
    const newHosts = comparable ? [...nowHosts].filter((h) => !thenHosts.has(h)).sort() : [];
    const removedHosts = comparable ? [...thenHosts].filter((h) => !nowHosts.has(h)).sort() : [];

    return {
        previousScanId: previous.id,
        previousDate: previous.createdAt,
        newHosts: newHosts.slice(0, MAX_CHANGE_ROWS),
        removedHosts: removedHosts.slice(0, MAX_CHANGE_ROWS),
        newServices: newServices.slice(0, MAX_CHANGE_ROWS),
        closedServices: closedServices.slice(0, MAX_CHANGE_ROWS),
        total: newHosts.length + removedHosts.length + newServices.length + closedServices.length,
    };
}

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
        return NextResponse.json({ ...scan, changes: await changesSincePrevious(scan) });
    } catch (error) {
        return handleError('GET /api/scans/[id]', error);
    }
}
