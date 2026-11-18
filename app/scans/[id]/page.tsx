"use client";

import { use, useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Clock, Info, Play, RefreshCw, Search, Timer } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import axios from 'axios';
import { type Finding } from '@/components/FindingCard';
import FindingGroupCard, { type DismissHandler } from '@/components/FindingGroupCard';
import { groupFindings } from '@/lib/group-findings';
import { ErrorBanner, StatusBadge } from '@/components/ui';
import { SEVERITIES, apiError, formatDateTime, formatDuration, portLabel, severityBar, severityLabel } from '@/lib/ui';

interface Scan {
    id: string;
    target: string;
    status: string;
    type: string;
    currentIndex: number;
    totalIps: number;
    portSpec?: string | null;
    udp?: boolean;
    pathNote?: string | null;
    startedAt: string | null;
    completedAt: string | null;
    createdAt: string;
    findings: Finding[];
    changes: Changes | null;
}

interface ServiceRef {
    ip: string;
    port: number;
    protocol?: string;
    service: string | null;
}

interface Changes {
    previousScanId: string;
    previousDate: string;
    newHosts: string[];
    removedHosts: string[];
    newServices: ServiceRef[];
    closedServices: ServiceRef[];
    total: number;
}

function ChangeList({ title, items, highlight }: { title: string; items: string[]; highlight?: boolean }) {
    if (items.length === 0) return null;
    return (
        <div>
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <span className={`h-2 w-2 rounded-full ${highlight ? 'bg-sev-critical' : 'bg-sev-low'}`} aria-hidden />
                {title} ({items.length})
            </p>
            <ul className="mt-2 space-y-1">
                {items.map((item) => <li key={item} className="break-all font-mono text-xs">{item}</li>)}
            </ul>
        </div>
    );
}

function ServiceChanges({ title, items, highlight }: { title: string; items: ServiceRef[]; highlight?: boolean }) {
    if (items.length === 0) return null;
    const groups = new Map<string, { label: string; ips: string[] }>();
    for (const s of items) {
        const label = `${portLabel(s.port, s.protocol)}${s.service ? ` ${s.service}` : ''}`;
        const g = groups.get(label);
        if (g) g.ips.push(s.ip); else groups.set(label, { label, ips: [s.ip] });
    }
    const list = [...groups.values()].sort((a, b) => b.ips.length - a.ips.length);
    return (
        <div>
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <span className={`h-2 w-2 rounded-full ${highlight ? 'bg-sev-critical' : 'bg-sev-low'}`} aria-hidden />
                {title} ({list.length})
            </p>
            <ul className="mt-2 space-y-1">
                {list.map((g) => (
                    <li key={g.label} className="font-mono text-xs">
                        {g.ips.length === 1 ? (
                            <span className="break-all">{g.ips[0]}:{g.label}</span>
                        ) : (
                            <details>
                                <summary className="cursor-pointer">{g.label} <span className="text-muted-foreground">on {g.ips.length} hosts</span></summary>
                                <p className="mt-1 max-h-40 overflow-y-auto break-words pl-3 text-muted-foreground">{g.ips.join(', ')}</p>
                            </details>
                        )}
                    </li>
                ))}
            </ul>
        </div>
    );
}

function ChangesPanel({ changes }: { changes: Changes }) {
    return (
        <section className="rounded-2xl border border-border bg-card p-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className="text-sm font-semibold">Changes since the previous scan</h2>
                <Link href={`/scans/${changes.previousScanId}`} className="text-xs text-muted-foreground underline decoration-secondary underline-offset-4 hover:text-foreground">
                    Compared with {formatDateTime(changes.previousDate)}
                </Link>
            </div>
            {changes.total === 0 ? (
                <p className="mt-3 text-sm text-muted-foreground">Nothing changed. The same hosts and services are exposed.</p>
            ) : (
                <div className="mt-4 grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
                    <ServiceChanges title="New services" items={changes.newServices} highlight />
                    <ChangeList title="New hostnames" items={changes.newHosts} highlight />
                    <ServiceChanges title="Closed services" items={changes.closedServices} />
                    <ChangeList title="Hostnames gone" items={changes.removedHosts} />
                </div>
            )}
        </section>
    );
}

const RESUMABLE = ['FAILED', 'TIMED_OUT', 'INTERRUPTED', 'PENDING'];
const STOPPED_NOTE: Record<string, string> = {
    TIMED_OUT: 'The scan passed the 30 minute limit. Results so far are shown below. Resume to continue from where it stopped.',
    INTERRUPTED: 'The server restarted while this scan was running. Resume to continue from where it stopped.',
    FAILED: 'The scan stopped on an unexpected error. Resume to continue from where it stopped.',
};

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const router = useRouter();
    const [scan, setScan] = useState<Scan | null>(null);
    const [loading, setLoading] = useState(true);
    const [notFound, setNotFound] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState('');
    const [busy, setBusy] = useState(false);
    const [now, setNow] = useState(() => Date.now());

    const fetchScan = useCallback(async () => {
        try {
            const res = await axios.get(`/api/scans/${id}`);
            setScan(res.data);
            setError(null);
        } catch (e) {
            if (axios.isAxiosError(e) && e.response?.status === 404) setNotFound(true);
            else setError(apiError(e, 'Could not load this scan.'));
        } finally {
            setLoading(false);
        }
    }, [id]);

    const status = scan?.status;
    const isLive = status === 'RUNNING' || status === 'PENDING';

    useEffect(() => {
        fetchScan();
    }, [fetchScan]);

    // Poll and tick the clock only while the scan is still moving.
    useEffect(() => {
        if (!isLive) return;
        const poll = setInterval(fetchScan, 3000);
        const clock = setInterval(() => setNow(Date.now()), 1000);
        return () => {
            clearInterval(poll);
            clearInterval(clock);
        };
    }, [isLive, fetchScan]);

    const handleAction = async (action: 'RESCAN' | 'RESUME') => {
        if (!scan) return;
        setBusy(true);
        setError(null);
        try {
            if (action === 'RESCAN') {
                const res = await axios.post('/api/scans', { target: scan.target });
                router.push(`/scans/${res.data.id}`);
            } else {
                await axios.post('/api/scans', { resumeId: scan.id });
                await fetchScan();
            }
        } catch (e) {
            setError(apiError(e, action === 'RESCAN' ? 'The rescan could not be started.' : 'The scan could not be resumed.'));
        } finally {
            setBusy(false);
        }
    };

    if (loading) return <p className="py-24 text-center text-sm text-muted-foreground">Loading scan...</p>;

    if (notFound || !scan) {
        return (
            <div className="space-y-4 py-24 text-center">
                <p className="text-sm text-muted-foreground">{notFound ? 'This scan does not exist.' : error}</p>
                <Link href="/scans" className="text-sm font-medium text-foreground underline decoration-secondary decoration-2 underline-offset-4 hover:decoration-foreground">Back to scans</Link>
            </div>
        );
    }

    const active = scan.findings.filter((f) => !f.dismissedAt);
    const dismissedGroups = groupFindings(scan.findings.filter((f) => f.dismissedAt));
    const dismiss: DismissHandler = async (ids, restore, reason) => {
        try {
            await axios.post('/api/findings/dismiss', { ids, restore, reason });
            await fetchScan();
        } catch (e) {
            setError(apiError(e, restore ? 'Could not restore the finding.' : 'Could not mark the finding as a false positive.'));
        }
    };

    const q = filter.trim().toLowerCase();
    const filteredFindings = active.filter((f) =>
        !q || [f.ip, String(f.port), portLabel(f.port, f.protocol), f.service, f.description, f.domains, f.vulnerability].some((v) => v?.toLowerCase().includes(q)));
    const groups = groupFindings(filteredFindings);
    const allGroups = groupFindings(active);
    const hostCount = new Set(active.map((f) => f.ip)).size;

    const progress = scan.totalIps > 0 ? Math.round((scan.currentIndex / scan.totalIps) * 100) : 0;
    const started = scan.startedAt ? new Date(scan.startedAt).getTime() : null;
    const ended = scan.completedAt ? new Date(scan.completedAt).getTime() : status === 'RUNNING' ? now : null;
    const elapsed = started && ended ? (ended - started) / 1000 : null;
    const eta = status === 'RUNNING' && started && scan.currentIndex > 0
        ? ((now - started) / scan.currentIndex) * (scan.totalIps - scan.currentIndex) / 1000
        : null;

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div className="flex min-w-0 items-start gap-3">
                    <Link href="/scans" aria-label="Back to scans" className="mt-0.5 rounded-full p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
                        <ArrowLeft className="h-5 w-5" />
                    </Link>
                    <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-3">
                            <h1 className="truncate font-mono text-3xl font-bold">{scan.target}</h1>
                            <StatusBadge status={scan.status} />
                        </div>
                        <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" aria-hidden /> {formatDateTime(scan.createdAt)}</span>
                            <span>{scan.type === 'SCHEDULED' ? 'Scheduled scan' : 'Manual scan'}</span>
                            <span className="min-w-0 break-all">TCP: {scan.portSpec || 'default list'}{scan.udp === false ? '' : ' · UDP probes'}</span>
                            {elapsed !== null && (
                                <span className="flex items-center gap-1.5 tabular-nums"><Timer className="h-3.5 w-3.5" aria-hidden /> {formatDuration(elapsed)}</span>
                            )}
                        </p>
                    </div>
                </div>

                <div className="flex shrink-0 gap-2">
                    {RESUMABLE.includes(scan.status) && (
                        <button
                            type="button"
                            onClick={() => handleAction('RESUME')}
                            disabled={busy}
                            className="flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
                        >
                            <Play className="h-4 w-4" aria-hidden />
                            Resume
                        </button>
                    )}
                    <button
                        type="button"
                        onClick={() => handleAction('RESCAN')}
                        disabled={busy || isLive}
                        className="flex items-center gap-2 rounded-full border border-border px-4 py-2 text-sm font-medium transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} aria-hidden />
                        Rescan
                    </button>
                </div>
            </div>

            <ErrorBanner message={error} />

            {status !== 'COMPLETED' && (
                <section className="rounded-2xl border border-border bg-card p-5">
                    <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold">{isLive ? 'Scanning' : 'Scan stopped'}</p>
                            {status === 'RUNNING' && (
                                <p className="mt-0.5 text-xs text-muted-foreground">
                                    Estimated time remaining: {eta !== null ? formatDuration(eta) : 'calculating'}
                                </p>
                            )}
                        </div>
                        <span className="font-mono text-sm tabular-nums">{scan.currentIndex} / {scan.totalIps} IPs</span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
                        <div className={`h-full transition-all duration-700 ${isLive ? 'bg-primary' : 'bg-sev-info'}`} style={{ width: `${progress}%` }} />
                    </div>
                    {STOPPED_NOTE[scan.status] && <p className="mt-3 text-sm text-muted-foreground">{STOPPED_NOTE[scan.status]}</p>}
                </section>
            )}

            {scan.pathNote && (
                <p className="flex gap-2 rounded-2xl border border-border bg-card p-4 text-sm text-muted-foreground">
                    <Info className="mt-0.5 h-4 w-4 shrink-0 text-foreground" aria-hidden />
                    <span className="whitespace-pre-line">{scan.pathNote}</span>
                </p>
            )}

            {scan.changes && <ChangesPanel changes={scan.changes} />}

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
                <aside className="h-fit rounded-2xl border border-border bg-card p-5">
                    <h2 className="text-sm font-semibold">Findings</h2>
                    <dl className="mt-4 space-y-3">
                        {SEVERITIES.map((sev) => (
                            <div key={sev} className="flex items-center justify-between">
                                <dt className="flex items-center gap-2 text-sm"><span className={`h-2.5 w-2.5 rounded-full ${severityBar[sev]}`} aria-hidden />{severityLabel(sev)}</dt>
                                <dd className="text-sm font-semibold tabular-nums">{allGroups.filter((g) => g.severity === sev).length}</dd>
                            </div>
                        ))}
                        <div className="flex items-center justify-between border-t border-border pt-3">
                            <dt className="text-sm text-muted-foreground">Total</dt>
                            <dd className="text-sm font-semibold tabular-nums">{allGroups.length}</dd>
                        </div>
                        <div className="flex items-center justify-between">
                            <dt className="text-sm text-muted-foreground">Hosts affected</dt>
                            <dd className="text-sm font-semibold tabular-nums">{hostCount}</dd>
                        </div>
                    </dl>
                </aside>

                <div className="space-y-4 lg:col-span-3">
                    <div className="relative">
                        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                        <input
                            type="search"
                            aria-label="Filter findings"
                            placeholder="Filter by IP, port, service, domain or issue"
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            className="w-full rounded-full border border-border bg-card py-2.5 pl-10 pr-4 text-sm outline-none transition-colors focus:border-primary"
                        />
                    </div>

                    {groups.map((group) => <FindingGroupCard key={group.key} group={group} onDismiss={dismiss} />)}

                    {filteredFindings.length === 0 && (
                        <p className="rounded-2xl border border-dashed border-border py-16 text-center text-sm text-muted-foreground">
                            {active.length > 0
                                ? 'No findings match that filter.'
                                : dismissedGroups.length > 0 ? 'Everything found here is marked as a false positive.'
                                : isLive ? 'No open services found yet.' : 'No open services were found on this target.'}
                        </p>
                    )}

                    {dismissedGroups.length > 0 && (
                        <details className="rounded-2xl border border-border bg-card">
                            <summary className="cursor-pointer px-5 py-3 text-sm font-medium text-muted-foreground">
                                False positives ({dismissedGroups.length})
                            </summary>
                            <div className="space-y-3 border-t border-border p-3">
                                {dismissedGroups.map((group) => <FindingGroupCard key={group.key} group={group} onDismiss={dismiss} dismissed />)}
                            </div>
                        </details>
                    )}
                </div>
            </div>
        </div>
    );
}
