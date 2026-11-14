"use client";

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ChevronDown, Flame, Globe, Loader2, Network, ScanSearch, Search, ShieldAlert } from 'lucide-react';
import axios from 'axios';
import { useRouter } from 'next/navigation';
import { splitList, type Finding } from '@/components/FindingCard';
import { ErrorBanner, PageHeader, SeverityBadge, StatCard } from '@/components/ui';
import { SEVERITY_RANK, apiError, formatDateTime, severityBar } from '@/lib/ui';

interface Host {
    ip: string;
    lastSeen: string;
    maxSeverity: string;
    domains: string[];
    techStack: string[];
    ports: { port: number; service: string | null; version: string | null; severity: string; description: string | null; issues: string[] }[];
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
            host = { ip: f.ip, lastSeen: f.updatedAt, maxSeverity: 'INFO', domains: [], techStack: [], ports: [] };
            hosts.set(f.ip, host);
        }
        const current = host;
        splitList(f.domains, ',').forEach((d) => { if (!current.domains.includes(d)) current.domains.push(d); });
        splitList(f.techStack, ',').forEach((t) => { if (!current.techStack.includes(t)) current.techStack.push(t); });
        current.ports.push({ port: f.port, service: f.service, version: f.version, severity: f.severity, description: f.description, issues: splitList(f.vulnerability, ';') });
        if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[current.maxSeverity] ?? 0)) current.maxSeverity = f.severity;
        if (f.updatedAt > current.lastSeen) current.lastSeen = f.updatedAt;
    }
    return Array.from(hosts.values())
        .map((h) => ({ ...h, ports: h.ports.sort((a, b) => a.port - b.port) }))
        .sort((a, b) =>
            (SEVERITY_RANK[b.maxSeverity] ?? 0) - (SEVERITY_RANK[a.maxSeverity] ?? 0) ||
            a.ip.localeCompare(b.ip, undefined, { numeric: true }));
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

    useEffect(() => {
        (async () => {
            try {
                const findings: Finding[] = (await axios.get('/api/findings')).data;
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
                setHosts(groupByHost(findings.filter((f) => f.ip !== '0.0.0.0')));
            } catch (e) {
                setError(apiError(e, 'Could not load the attack surface.'));
            } finally {
                setLoading(false);
            }
        })();
    }, []);

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
                                            onClick={() => startScan(host.ip)}
                                            disabled={scanning !== null}
                                            aria-label={`Rescan ${host.ip}`}
                                            title="Rescan this host"
                                            className="shrink-0 rounded-full border border-border p-2 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
                                        >
                                            {scanning === host.ip ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
                                        </button>
                                    </div>

                                    {isOpen && (
                                        <div className="space-y-4 border-t border-border bg-background/40 p-4">
                                            {host.domains.length > 0 && (
                                                <div>
                                                    <p className="mb-2 text-xs font-semibold text-muted-foreground">Hostnames (select one to scan it)</p>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {host.domains.map((d) => (
                                                            <button
                                                                key={d}
                                                                type="button"
                                                                onClick={() => startScan(d)}
                                                                disabled={scanning !== null}
                                                                className="rounded-full border border-border bg-muted px-2 py-1 font-mono text-xs transition-colors hover:border-secondary hover:bg-accent disabled:opacity-50"
                                                            >
                                                                {d}
                                                            </button>
                                                        ))}
                                                    </div>
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

                                            <p className="text-xs text-muted-foreground">Last seen {formatDateTime(host.lastSeen)}</p>
                                        </div>
                                    )}
                                </div>
                            </article>
                        );
                    })
                )}
            </div>
        </div>
    );
}
