import { prisma } from './prisma';
import { checkPath, describePathCheck, getTargetIps, type PathCheck, scanIp, UDP_PROBE_PORTS, type ScanResult, type TargetResolution } from './scanner';
import { MAX_PROBES_PER_SCAN, parsePortSpec, PortSpecError } from './ports';

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
        where: { ip_port_protocol: { ip: f.ip, port: f.port, protocol: f.protocol ?? 'tcp' } },
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
        closedAt: null,
        scans: { connect: { id: scanId } },
    };

    await prisma.finding.upsert({
        where: { ip_port_protocol: { ip: f.ip, port: f.port, protocol: f.protocol ?? 'tcp' } },
        update: data,
        create: { ip: f.ip, port: f.port, protocol: f.protocol ?? 'tcp', ...data },
    });
}

/**
 * Marks known ports on the host as closed when this scan checked them and they
 * did not answer. Ports outside the scanned list are left alone, so a scan of
 * 8000-8100 does not close port 22.
 */
export async function markClosed(ip: string, protocol: 'tcp' | 'udp', scannedPorts: number[], openPorts: number[]) {
    const scanned = new Set(scannedPorts);
    const open = new Set(openPorts);
    const known = await prisma.finding.findMany({
        // Port 0 is the DNS reconnaissance pseudo finding, not a service.
        where: { ip, protocol, closedAt: null, port: { not: 0 } },
        select: { id: true, port: true },
    });
    const ids = known.filter((f) => scanned.has(f.port) && !open.has(f.port)).map((f) => f.id);
    if (ids.length === 0) return;
    await prisma.finding.updateMany({ where: { id: { in: ids } }, data: { closedAt: new Date() } });
}

export interface PortOptions {
    /** TCP port spec such as "default, 8000-8100". Empty means the default list. */
    ports?: string | null;
    /** Run the UDP service probes. Defaults to true. */
    udp?: boolean;
}

/** Parses the port spec into a list, turning bad input into a 400 for the caller. */
export function resolvePorts(spec: string | null | undefined, ipCount = 1): number[] {
    let ports: number[];
    try {
        ports = parsePortSpec(spec);
    } catch (error) {
        if (error instanceof PortSpecError) throw new ScanError(error.message, 400);
        throw error;
    }
    if (ports.length * ipCount > MAX_PROBES_PER_SCAN) {
        throw new ScanError(
            `${ipCount} hosts x ${ports.length} ports is ${(ports.length * ipCount).toLocaleString('en')} checks. ` +
            `The limit is ${MAX_PROBES_PER_SCAN.toLocaleString('en')} per scan, so use fewer ports or a smaller range of hosts.`,
            400,
        );
    }
    return ports;
}

async function runScan(scanId: string) {
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return;

    const ips = parseJson<string[]>(scan.ipList, []);
    const mappings = parseJson<Record<string, string[]>>(scan.hostMap, {});
    const startTime = Date.now();
    const requested = parsePortSpec(scan.portSpec);

    await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'RUNNING', startedAt: scan.startedAt ?? new Date(), completedAt: null },
    });

    // Ports the network path answers for any address are left out, otherwise every host
    // in the range would show them open. Findings on those ports are closed below, since
    // they cannot be told apart from the interception.
    const path: PathCheck = await checkPath(requested, scan.udp).catch(() => ({ tcp: [], udp: [] }));
    const ports = requested.filter((p) => !path.tcp.includes(p));
    await prisma.scan.update({ where: { id: scanId }, data: { pathNote: describePathCheck(path) } });

    for (let i = scan.currentIndex; i < ips.length; i++) {
        if (Date.now() - startTime > SCAN_TIMEOUT_MS) {
            await prisma.scan.update({ where: { id: scanId }, data: { status: 'TIMED_OUT' } });
            return;
        }

        const ip = ips[i];
        const hostnames = mappings[ip] || [];

        let results: ScanResult[] = [];
        let scanned = false;
        try {
            results = await scanIp(ip, hostnames[0], { ports, udp: scan.udp, skipUdp: path.udp });
            scanned = true;
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

        // Ports seen before that did not answer this time are marked closed rather than
        // deleted, so the history stays and they come back if they open again.
        if (scanned) {
            const openOn = (protocol: string) => results.filter((r) => (r.protocol ?? 'tcp') === protocol).map((r) => r.port);
            await Promise.all([
                markClosed(ip, 'tcp', requested, openOn('tcp')),
                scan.udp ? markClosed(ip, 'udp', UDP_PROBE_PORTS, openOn('udp')) : null,
            ]).catch((error) => {
                console.error(`[scan ${scanId}] could not mark closed ports on ${ip}:`, error);
            });
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

    const section = (title: string, lines: string[]) => (lines.length > 0 ? [`=== ${title} ===`, ...lines, ''] : []);
    const forensics = [
        ...section('DNS RECORDS', pick('A Records', 'CNAME Chain', 'Nameservers', 'MX Record', 'SRV Record', 'Wildcard DNS', 'Reverse DNS', 'Skipped')),
        ...section('SUBDOMAINS', pick('Certificate logs', 'Subdomain [', 'AI name suggestions')),
        ...section('STALE NAMES', pick('Stale name')),
        ...section('HOSTING AND THIRD PARTIES', pick('Alias:', 'Network owner', 'SaaS in use', 'Third-party sender', 'Declared mail range', 'Related domain')),
        ...section('EMAIL SECURITY', pick('SPF Record', 'DMARC', 'DKIM', 'Email Security')),
        ...section('TLS/SSL ANALYSIS', pick('SSL')),
    ].join('\n').trim();

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
        where: { ip_port_protocol: { ip: '0.0.0.0', port: 0, protocol: 'tcp' } },
        update: data,
        create: { ip: '0.0.0.0', port: 0, ...data },
    });
}

/** Validates the target, records the scan and starts it in the background. */
export async function startScan(rawTarget: string, type: 'MANUAL' | 'SCHEDULED' = 'MANUAL', options: PortOptions = {}) {
    assertCapacity();
    const portSpec = options.ports?.trim() || null;
    resolvePorts(portSpec); // fail fast on bad input before any DNS work
    const resolution = await getTargetIps(rawTarget);
    if (resolution.ips.length === 0) {
        throw new ScanError('Could not resolve any scannable IP addresses for that target.', 400);
    }
    resolvePorts(portSpec, resolution.ips.length);
    assertCapacity();

    const scan = await prisma.scan.create({
        data: {
            target: resolution.target,
            status: 'PENDING',
            type,
            totalIps: resolution.ips.length,
            ipList: JSON.stringify(resolution.ips),
            hostMap: JSON.stringify(resolution.mappings),
            portSpec,
            udp: options.udp ?? true,
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
