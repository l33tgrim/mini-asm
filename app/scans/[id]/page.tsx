"use client";

import { use, useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Clock, Play, RefreshCw, Search, Timer } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import axios from 'axios';
import FindingCard, { type Finding } from '@/components/FindingCard';
import { ErrorBanner, StatusBadge } from '@/components/ui';
import { SEVERITIES, apiError, formatDateTime, formatDuration, severityBar, severityLabel } from '@/lib/ui';

interface Scan {
    id: string;
    target: string;
    status: string;
    type: string;
    currentIndex: number;
    totalIps: number;
    startedAt: string | null;
    completedAt: string | null;
    createdAt: string;
    findings: Finding[];
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

    const q = filter.trim().toLowerCase();
    const filteredFindings = scan.findings.filter((f) =>
        !q || [f.ip, String(f.port), f.service, f.description, f.domains, f.vulnerability].some((v) => v?.toLowerCase().includes(q)));

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

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
                <aside className="h-fit rounded-2xl border border-border bg-card p-5">
                    <h2 className="text-sm font-semibold">Findings</h2>
                    <dl className="mt-4 space-y-3">
                        {SEVERITIES.map((sev) => (
                            <div key={sev} className="flex items-center justify-between">
                                <dt className="flex items-center gap-2 text-sm"><span className={`h-2.5 w-2.5 rounded-full ${severityBar[sev]}`} aria-hidden />{severityLabel(sev)}</dt>
                                <dd className="text-sm font-semibold tabular-nums">{scan.findings.filter((f) => f.severity === sev).length}</dd>
                            </div>
                        ))}
                        <div className="flex items-center justify-between border-t border-border pt-3">
                            <dt className="text-sm text-muted-foreground">Total</dt>
                            <dd className="text-sm font-semibold tabular-nums">{scan.findings.length}</dd>
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

                    {filteredFindings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}

                    {filteredFindings.length === 0 && (
                        <p className="rounded-2xl border border-dashed border-border py-16 text-center text-sm text-muted-foreground">
                            {scan.findings.length > 0
                                ? 'No findings match that filter.'
                                : isLive ? 'No open services found yet.' : 'No open services were found on this target.'}
                        </p>
                    )}
                </div>
            </div>
        </div>
    );
}
