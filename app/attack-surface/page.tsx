"use client";

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ChevronDown, Crosshair, Flame, Globe, Loader2, Network, RefreshCw, ScanSearch, Search, ShieldAlert } from 'lucide-react';
import axios from 'axios';
import { useRouter } from 'next/navigation';
import { splitList, type Finding } from '@/components/FindingCard';
import { ErrorBanner, PageHeader, SeverityBadge, StatCard } from '@/components/ui';
import { ThreatScenarioDialog } from '@/components/ThreatScenarioDialog';
import { SEVERITY_RANK, apiError, formatDateTime, severityBar } from '@/lib/ui';

interface Host {
    ip: string;
    lastSeen: string;
    maxSeverity: string;
    domains: string[];
    techStack: string[];
    ports: { port: number; service: string | null; version: string | null; severity: string; description: string | null; issues: string[] }[];
    closed: { port: number; service: string | null; closedAt: string }[];
}

interface RescanResult {
    at: string;
    open: number;
    opened: number[];
    closed: number[];
    failed?: string;
}

interface Recon {
    description: string;
    severity: string;
    issues: string[];
    forensics: string;
}

function groupByHost(findings: Finding[]): Host[] {
    const hosts = new Map<string, Host>();
    for (const f of findings) {
        let host = hosts.get(f.ip);
        if (!host) {
            host = { ip: f.ip, lastSeen: f.updatedAt, maxSeverity: 'INFO', domains: [], techStack: [], ports: [], closed: [] };
            hosts.set(f.ip, host);
        }
        const current = host;
        splitList(f.domains, ',').forEach((d) => { if (!current.domains.includes(d)) current.domains.push(d); });
        splitList(f.techStack, ',').forEach((t) => { if (!current.techStack.includes(t)) current.techStack.push(t); });
        if (f.updatedAt > current.lastSeen) current.lastSeen = f.updatedAt;
        if (f.closedAt) {
            current.closed.push({ port: f.port, service: f.service, closedAt: f.closedAt });
            continue;
        }
        current.ports.push({ port: f.port, service: f.service, version: f.version, severity: f.severity, description: f.description, issues: splitList(f.vulnerability, ';') });
        if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[current.maxSeverity] ?? 0)) current.maxSeverity = f.severity;
    }
    return Array.from(hosts.values())
        .map((h) => ({ ...h, ports: h.ports.sort((a, b) => a.port - b.port), closed: h.closed.sort((a, b) => a.port - b.port) }))
        .sort((a, b) =>
            (SEVERITY_RANK[b.maxSeverity] ?? 0) - (SEVERITY_RANK[a.maxSeverity] ?? 0) ||
            a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

const now = () => new Date().toISOString();

/** Polls a scan until it stops running, for up to five minutes. Returns its last status. */
async function waitForScan(id: string): Promise<string> {
    const deadline = Date.now() + 5 * 60 * 1000;
    let status = 'PENDING';
    while (['PENDING', 'RUNNING'].includes(status) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 1500));
        status = (await axios.get(`/api/scans/${id}`)).data.status;
    }
    return status;
}

export default function AttackSurfacePage() {
    const router = useRouter();
    const [hosts, setHosts] = useState<Host[]>([]);
    const [recon, setRecon] = useState<Recon | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState('');
    const [scanning, setScanning] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [testing, setTesting] = useState<{ target: string; ports: Host['ports'] } | null>(null);
    const [rescanning, setRescanning] = useState<Set<string>>(new Set());
    const [rescans, setRescans] = useState<Record<string, RescanResult>>({});

    const load = async () => {
        const findings: Finding[] = (await axios.get('/api/findings?closed=1')).data;
        // 0.0.0.0 holds the DNS reconnaissance summary from the latest domain scan.
        const summary = findings.find((f) => f.ip === '0.0.0.0');
        if (summary) {
            setRecon({
                description: summary.description || '',
                severity: summary.severity,
                issues: splitList(summary.vulnerability, ';'),
                forensics: summary.forensics || '',
            });
        }
        const next = groupByHost(findings.filter((f) => f.ip !== '0.0.0.0'));
        setHosts(next);
        return next;
    };

    useEffect(() => {
        (async () => {
            try {
                await load();
            } catch (e) {
                setError(apiError(e, 'Could not load the attack surface.'));
            } finally {
                setLoading(false);
            }
        })();
    }, []);

    /** Rescans one IP on the page and reports which ports opened or closed since the last look. */
    const rescanHost = async (ip: string) => {
        const before = new Set(hosts.find((h) => h.ip === ip)?.ports.map((p) => p.port) ?? []);
        setRescanning((s) => new Set(s).add(ip));
        setRescans((r) => { const rest = { ...r }; delete rest[ip]; return rest; });
        let result: RescanResult;
        try {
            const { id } = (await axios.post('/api/scans', { target: ip })).data;
            const status = await waitForScan(id);
            if (status !== 'COMPLETED') throw new Error(status === 'PENDING' || status === 'RUNNING' ? 'The rescan is taking longer than expected. Check Scans for progress.' : `The rescan ended as ${status.toLowerCase()}.`);
            const after = new Set((await load()).find((h) => h.ip === ip)?.ports.map((p) => p.port) ?? []);
            result = {
                at: now(),
                open: after.size,
                opened: [...after].filter((p) => !before.has(p)).sort((a, b) => a - b),
                closed: [...before].filter((p) => !after.has(p)).sort((a, b) => a - b),
            };
        } catch (e) {
            result = { at: now(), open: before.size, opened: [], closed: [], failed: e instanceof Error && !axios.isAxiosError(e) ? e.message : apiError(e, 'The rescan could not start.') };
        }
        setRescans((r) => ({ ...r, [ip]: result }));
        setRescanning((s) => { const n = new Set(s); n.delete(ip); return n; });
    };

    const startScan = async (target: string) => {
        setScanning(target);
        setError(null);
        try {
            const res = await axios.post('/api/scans', { target });
            router.push(`/scans/${res.data.id}`);
        } catch (e) {
            setError(apiError(e, `Could not start a scan of ${target}.`));
            setScanning(null);
        }
    };

    const filteredHosts = useMemo(() => {
        const q = filter.trim().toLowerCase();
        if (!q) return hosts;
        return hosts.filter((h) =>
            h.ip.includes(q) ||
            h.domains.some((d) => d.includes(q)) ||
            h.ports.some((p) => p.service?.toLowerCase().includes(q) || String(p.port) === q));
    }, [hosts, filter]);

    const openPorts = hosts.reduce((acc, h) => acc + h.ports.length, 0);
    const critical = hosts.filter((h) => h.maxSeverity === 'CRITICAL').length;
    const high = hosts.filter((h) => h.maxSeverity === 'HIGH').length;

    return (
        <div className="space-y-6">
            <PageHeader title="Attack surface" description="Hosts discovered so far, grouped by IP address and ordered by risk">
                <div className="relative w-full sm:w-72">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                    <input
                        type="search"
                        aria-label="Search hosts"
                        placeholder="Search IP, domain or service"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="w-full rounded-full border border-border bg-card py-2 pl-10 pr-4 text-sm outline-none transition-colors focus:border-primary"
                    />
                </div>
            </PageHeader>

            <ErrorBanner message={error} />

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label="Hosts" value={hosts.length} icon={Globe} />
                <StatCard label="Open ports" value={openPorts} icon={Network} />
                <StatCard label="Critical hosts" value={critical} icon={AlertTriangle} />
                <StatCard label="High risk hosts" value={high} icon={Flame} />
            </div>

            {recon && (
                <section className="rounded-2xl border border-border bg-card p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                            <h2 className="text-sm font-semibold">Domain reconnaissance</h2>
                            <p className="mt-1 text-sm text-muted-foreground">{recon.description}</p>
                        </div>
                        {recon.issues.length > 0 && <SeverityBadge severity={recon.severity} />}
                    </div>
                    {recon.issues.length > 0 && (
                        <ul className="mt-3 space-y-1">
                            {recon.issues.map((issue) => (
                                <li key={issue} className="flex items-start gap-2 text-sm">
                                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sev-critical" aria-hidden />
                                    {issue}
                                </li>
                            ))}
                        </ul>
                    )}
                    {recon.forensics && (
                        <details className="group mt-3">
                            <summary className="flex w-fit list-none items-center gap-1 text-xs font-medium text-foreground underline decoration-secondary decoration-2 underline-offset-4 hover:decoration-foreground">
                                <ChevronDown className="h-3 w-3 transition-transform group-open:rotate-180" aria-hidden />
                                Discovery details
                            </summary>
                            <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-background p-3 font-mono text-xs text-muted-foreground">{recon.forensics}</pre>
                        </details>
                    )}
                </section>
            )}

            <div className="space-y-3">
                {loading ? (
                    <p className="rounded-2xl border border-border bg-card p-12 text-center text-sm text-muted-foreground">Loading hosts...</p>
                ) : filteredHosts.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-border bg-card p-12 text-center">
                        <Globe className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" aria-hidden />
                        <p className="text-sm text-muted-foreground">
                            {hosts.length === 0 ? 'No hosts discovered yet. Run a scan to map your attack surface.' : 'No hosts match that search.'}
                        </p>
                    </div>
                ) : (
                    filteredHosts.map((host) => {
                        const isOpen = expanded === host.ip;
                        const issueCount = host.ports.reduce((a, p) => a + p.issues.length, 0);
                        const busy = rescanning.has(host.ip);
                        const result = rescans[host.ip];
                        return (
                            <article key={host.ip} className="flex overflow-hidden rounded-2xl border border-border bg-card">
                                <div className={`w-1 shrink-0 ${severityBar[host.maxSeverity] ?? severityBar.INFO}`} aria-hidden />
                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-2 p-4">
                                        <button
                                            type="button"
                                            onClick={() => setExpanded(isOpen ? null : host.ip)}
                                            aria-expanded={isOpen}
                                            className="flex min-w-0 flex-1 items-center justify-between gap-4 text-left"
                                        >
                                            <div className="min-w-0">
                                                <div className="flex flex-wrap items-center gap-2">
                                                    <span className="font-mono font-semibold">{host.ip}</span>
                                                    <SeverityBadge severity={host.maxSeverity} />
                                                </div>
                                                {host.domains.length > 0 && (
                                                    <p className="mt-1 truncate text-xs text-muted-foreground">
                                                        {host.domains.slice(0, 4).join(', ')}{host.domains.length > 4 ? ` +${host.domains.length - 4} more` : ''}
                                                    </p>
                                                )}
                                            </div>
                                            <div className="flex shrink-0 items-center gap-5 text-right">
                                                <div>
                                                    <p className="text-sm font-semibold tabular-nums">{host.ports.length}</p>
                                                    <p className="text-[11px] text-muted-foreground">Ports</p>
                                                </div>
                                                <div>
                                                    <p className="text-sm font-semibold tabular-nums">{issueCount}</p>
                                                    <p className="text-[11px] text-muted-foreground">Issues</p>
                                                </div>
                                                <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${isOpen ? 'rotate-180' : ''}`} aria-hidden />
                                            </div>
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setTesting({ target: host.ip, ports: host.ports })}
                                            aria-label={`Threat scenarios for ${host.ip}`}
                                            title="Run threat scenarios against this host"
                                            className="shrink-0 rounded-full border border-border p-2 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                                        >
                                            <Crosshair className="h-4 w-4" />
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => rescanHost(host.ip)}
                                            disabled={busy}
                                            aria-label={`Rescan ${host.ip}`}
                                            title="Rescan the ports on this IP and update the card"
                                            className="flex shrink-0 items-center gap-1.5 rounded-full border border-border p-2 text-xs font-medium text-muted-foreground transition-colors hover:border-secondary hover:bg-accent hover:text-foreground disabled:opacity-60 sm:px-3"
                                        >
                                            <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} aria-hidden />
                                            <span className="hidden sm:inline">{busy ? 'Rescanning' : 'Rescan'}</span>
                                        </button>
                                    </div>

                                    {(busy || result) && (
                                        <div role="status" className="-mt-1 px-4 pb-3 text-xs text-muted-foreground">
                                            {busy ? (
                                                <span className="flex items-center gap-1.5"><Loader2 className="h-3 w-3 animate-spin" aria-hidden /> Checking {host.ip}. This usually takes under a minute.</span>
                                            ) : result?.failed ? (
                                                <span className="text-sev-critical">{result.failed}</span>
                                            ) : result && (
                                                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                                                    <span>Rescanned {formatDateTime(result.at)}: {result.open} open</span>
                                                    {result.opened.length > 0 && <span className="font-medium text-foreground">Newly open: {result.opened.join(', ')}</span>}
                                                    {result.closed.length > 0 && <span>Now closed: {result.closed.join(', ')}</span>}
                                                    {result.opened.length === 0 && result.closed.length === 0 && <span>No change</span>}
                                                </span>
                                            )}
                                        </div>
                                    )}

                                    {isOpen && (
                                        <div className="space-y-4 border-t border-border bg-background/40 p-4">
                                            {host.domains.length > 0 && (
                                                <div>
                                                    <p className="mb-2 text-xs font-semibold text-muted-foreground">Hostnames</p>
                                                    <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
                                                        {host.domains.map((d) => (
                                                            <li key={d} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                                                                <span className="min-w-0 break-all font-mono text-xs">{d}</span>
                                                                <span className="flex shrink-0 gap-1.5">
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => setTesting({ target: d, ports: host.ports })}
                                                                        className="flex items-center gap-1 rounded-full bg-primary px-2.5 py-1 text-xs font-medium text-primary-foreground transition-opacity hover:opacity-90"
                                                                    >
                                                                        <Crosshair className="h-3 w-3" aria-hidden /> Threat scenarios
                                                                    </button>
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => startScan(d)}
                                                                        disabled={scanning !== null}
                                                                        className="flex items-center gap-1 rounded-full border border-border px-2.5 py-1 text-xs transition-colors hover:border-secondary hover:bg-accent disabled:opacity-50"
                                                                    >
                                                                        {scanning === d ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden /> : <ScanSearch className="h-3 w-3" aria-hidden />} Scan
                                                                    </button>
                                                                </span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            {host.techStack.length > 0 && (
                                                <div>
                                                    <p className="mb-2 text-xs font-semibold text-muted-foreground">Technology</p>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {host.techStack.map((t) => (
                                                            <span key={t} className="rounded-full border border-border bg-muted px-2 py-1 text-xs text-muted-foreground">{t}</span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            <div>
                                                <p className="mb-2 text-xs font-semibold text-muted-foreground">Open services</p>
                                                {host.ports.length === 0 && (
                                                    <p className="rounded-lg border border-dashed border-border bg-card p-3 text-xs text-muted-foreground">
                                                        No ports answered on the last scan. The host may be down, or a firewall may be dropping the probes.
                                                    </p>
                                                )}
                                                <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
                                                    {host.ports.map((p) => (
                                                        <li key={p.port} className="p-3">
                                                            <div className="flex items-start justify-between gap-3">
                                                                <div className="min-w-0">
                                                                    <p className="text-sm">
                                                                        <span className="font-mono font-semibold">{p.port}</span>
                                                                        <span className="ml-2">{p.service || 'Unknown'}</span>
                                                                        {p.version && <span className="ml-2 font-mono text-xs text-muted-foreground">v{p.version}</span>}
                                                                    </p>
                                                                    {p.description && <p className="mt-0.5 break-words text-xs text-muted-foreground">{p.description}</p>}
                                                                </div>
                                                                <SeverityBadge severity={p.severity} />
                                                            </div>
                                                            {p.issues.length > 0 && (
                                                                <ul className="mt-2 space-y-1">
                                                                    {p.issues.map((issue) => (
                                                                        <li key={issue} className="flex items-start gap-2 text-xs">
                                                                            <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0 text-sev-critical" aria-hidden />
                                                                            {issue}
                                                                        </li>
                                                                    ))}
                                                                </ul>
                                                            )}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>

                                            {host.closed.length > 0 && (
                                                <div>
                                                    <p className="mb-2 text-xs font-semibold text-muted-foreground">Closed since an earlier scan</p>
                                                    <ul className="flex flex-wrap gap-1.5">
                                                        {host.closed.map((p) => (
                                                            <li key={p.port} title={`Not answering since ${formatDateTime(p.closedAt)}`} className="rounded-full border border-border bg-muted px-2 py-1 text-xs text-muted-foreground">
                                                                <span className="font-mono">{p.port}</span> {p.service || 'Unknown'}
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            <p className="text-xs text-muted-foreground">Last seen {formatDateTime(host.lastSeen)}</p>
                                        </div>
                                    )}
                                </div>
                            </article>
                        );
                    })
                )}
            </div>
            {testing && <ThreatScenarioDialog target={testing.target} ports={testing.ports} onClose={() => setTesting(null)} />}
        </div>
    );
}
