import { prisma } from './prisma';
import { getTargetIps, scanIp, type ScanResult, type TargetResolution } from './scanner';

export const MAX_CONCURRENT_SCANS = 3;
const SCAN_TIMEOUT_MS = 30 * 60 * 1000;
export const RESUMABLE_STATUSES = ['PENDING', 'FAILED', 'TIMED_OUT', 'INTERRUPTED'];

/** Raised when a scan cannot be started for a reason the caller should see. */
export class ScanError extends Error {
    constructor(message: string, public status: number) {
        super(message);
    }
}

// Scans run inside this server process, so the set of live scans is process state.
// It is kept on globalThis so hot reloads in development do not lose track of it.
const globalState = globalThis as unknown as { __asmActiveScans?: Set<string> };
const activeScans = (globalState.__asmActiveScans ??= new Set<string>());

function parseJson<T>(value: string | null, fallback: T): T {
    if (!value) return fallback;
    try {
        return JSON.parse(value) as T;
    } catch {
        return fallback;
    }
}

async function saveFinding(scanId: string, f: ScanResult, extraDomains: string[]) {
    const existing = await prisma.finding.findUnique({
        where: { ip_port: { ip: f.ip, port: f.port } },
        select: { domains: true },
    });
    const domainSet = new Set((existing?.domains || '').split(',').filter(Boolean));
    extraDomains.forEach((d) => domainSet.add(d.toLowerCase()));

    const data = {
        service: f.service,
        version: f.version ?? null,
        banner: f.banner ?? null,
        severity: f.severity,
        description: f.description,
        vulnerability: f.vulnerability ?? null,
        remediation: f.remediation ?? null,
        forensics: f.forensics ?? null,
        upstreamVersion: f.upstreamVersion ?? null,
        domains: Array.from(domainSet).join(',') || null,
        techStack: f.techStack ?? null,
        scans: { connect: { id: scanId } },
    };

    await prisma.finding.upsert({
        where: { ip_port: { ip: f.ip, port: f.port } },
        update: data,
        create: { ip: f.ip, port: f.port, ...data },
    });
}

async function runScan(scanId: string) {
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return;

    const ips = parseJson<string[]>(scan.ipList, []);
    const mappings = parseJson<Record<string, string[]>>(scan.hostMap, {});
    const startTime = Date.now();

    await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'RUNNING', startedAt: scan.startedAt ?? new Date(), completedAt: null },
    });

    for (let i = scan.currentIndex; i < ips.length; i++) {
        if (Date.now() - startTime > SCAN_TIMEOUT_MS) {
            await prisma.scan.update({ where: { id: scanId }, data: { status: 'TIMED_OUT' } });
            return;
        }

        const ip = ips[i];
        const hostnames = mappings[ip] || [];

        let results: ScanResult[] = [];
        try {
            results = await scanIp(ip, hostnames[0]);
        } catch (error) {
            // One unreachable host must not abort the whole scan.
            console.error(`[scan ${scanId}] error scanning ${ip}:`, error);
        }

        for (const finding of results) {
            try {
                await saveFinding(scanId, finding, hostnames);
            } catch (error) {
                console.error(`[scan ${scanId}] could not save ${finding.ip}:${finding.port}:`, error);
            }
        }

        await prisma.scan.update({ where: { id: scanId }, data: { currentIndex: i + 1 } });
    }

    await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'COMPLETED', completedAt: new Date() },
    });
}

function launch(scanId: string) {
    activeScans.add(scanId);
    runScan(scanId)
        .catch(async (error) => {
            console.error(`[scan ${scanId}] failed:`, error);
            await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED' } }).catch(() => { });
        })
        .finally(() => activeScans.delete(scanId));
}

function assertCapacity() {
    if (activeScans.size >= MAX_CONCURRENT_SCANS) {
        throw new ScanError(`${MAX_CONCURRENT_SCANS} scans are already running. Wait for one to finish.`, 429);
    }
}

async function saveDiscoveryFinding(scanId: string, resolution: TargetResolution) {
    const details = resolution.discoveryDetails;
    const pick = (...needles: string[]) => details.filter((d) => needles.some((n) => d.includes(n)));

    const warnings = details.filter((d) => d.includes('⚠️'));
    let severity = 'INFO';
    if (warnings.length > 0) severity = 'MEDIUM';
    if (warnings.some((d) => d.includes('expired'))) severity = 'HIGH';

    const forensics = [
        '=== DNS DISCOVERY ===',
        ...pick('A Records', 'CNAME', 'Nameservers', 'MX Record', 'Wildcard DNS', 'Discovered Subdomain', 'Reverse DNS', 'Skipped'),
        '',
        '=== EMAIL SECURITY ===',
        ...pick('SPF', 'DMARC', 'Email Security'),
        '',
        '=== TLS/SSL ANALYSIS ===',
        ...pick('SSL'),
    ].join('\n');

    const data = {
        service: 'DNS Discovery',
        severity,
        description: `Domain reconnaissance for ${resolution.target}. Discovered ${resolution.ips.length} IP addresses and ${resolution.subdomainCount} subdomains.`,
        vulnerability: warnings.map((d) => d.replace('⚠️ ', '')).join('; ') || null,
        forensics,
        domains: resolution.target,
        scans: { connect: { id: scanId } },
    };

    // The reconnaissance summary is stored as a pseudo finding on 0.0.0.0:0.
    await prisma.finding.upsert({
        where: { ip_port: { ip: '0.0.0.0', port: 0 } },
        update: data,
        create: { ip: '0.0.0.0', port: 0, ...data },
    });
}

/** Validates the target, records the scan and starts it in the background. */
export async function startScan(rawTarget: string, type: 'MANUAL' | 'SCHEDULED' = 'MANUAL') {
    assertCapacity();
    const resolution = await getTargetIps(rawTarget);
    if (resolution.ips.length === 0) {
        throw new ScanError('Could not resolve any scannable IP addresses for that target.', 400);
    }
    assertCapacity();

    const scan = await prisma.scan.create({
        data: {
            target: resolution.target,
            status: 'PENDING',
            type,
            totalIps: resolution.ips.length,
            ipList: JSON.stringify(resolution.ips),
            hostMap: JSON.stringify(resolution.mappings),
        },
    });

    if (resolution.kind === 'domain' && resolution.discoveryDetails.length > 0) {
        await saveDiscoveryFinding(scan.id, resolution).catch((error) => {
            console.error(`[scan ${scan.id}] could not save discovery summary:`, error);
        });
    }

    launch(scan.id);
    return scan;
}

/** Continues a scan that stopped before finishing. */
export async function resumeScan(scanId: string) {
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) throw new ScanError('Scan not found.', 404);
    if (activeScans.has(scanId) || !RESUMABLE_STATUSES.includes(scan.status)) {
        throw new ScanError('Only scans that stopped before finishing can be resumed.', 409);
    }
    assertCapacity();
    launch(scanId);
    return scan;
}

/** Scans cannot survive a restart. Mark anything left as RUNNING so the UI offers a resume. */
export async function recoverInterruptedScans() {
    const stale = await prisma.scan.findMany({
        where: { status: { in: ['RUNNING', 'PENDING'] } },
        select: { id: true },
    });
    const ids = stale.map((s) => s.id).filter((id) => !activeScans.has(id));
    if (ids.length === 0) return;
    await prisma.scan.updateMany({ where: { id: { in: ids } }, data: { status: 'INTERRUPTED' } });
    console.log(`[scan] marked ${ids.length} unfinished scan(s) as INTERRUPTED after restart`);
}
