"use client";

import { useCallback, useEffect, useState } from 'react';
import { ScanSearch, Play, Search, Info, RefreshCw, ChevronRight, Activity, CheckCircle2, Loader2, ShieldAlert, ListChecks } from 'lucide-react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import axios from 'axios';
import { ErrorBanner, IconButton, PageHeader, StatCard, StatusBadge } from '@/components/ui';
import { apiError, formatDateTime } from '@/lib/ui';
import { DEFAULT_TCP_PORTS, PORT_PRESETS, parsePortSpec } from '@/lib/ports';

const UDP_SERVICES = 'DNS 53, NTP 123, SNMP 161, SSDP 1900, SIP 5060, memcached 11211';

/** Builds the spec the API takes from the chosen presets and the custom box. */
function buildSpec(presets: string[], custom: string): string {
    return [...presets, custom.trim()].filter(Boolean).join(', ');
}

function countPorts(spec: string): { count: number; error?: string } {
    if (!spec) return { count: 0, error: 'Pick a preset or type some ports.' };
    try {
        return { count: parsePortSpec(spec).length };
    } catch (e) {
        return { count: 0, error: (e as Error).message };
    }
}

interface Scan {
    id: string;
    target: string;
    status: string;
    type: string;
    createdAt: string;
    totalIps: number;
    currentIndex: number;
    _count?: { findings: number };
}

export default function ScansPage() {
    const router = useRouter();
    const [scans, setScans] = useState<Scan[]>([]);
    const [target, setTarget] = useState('');
    const [isStarting, setIsStarting] = useState(false);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [formError, setFormError] = useState<string | null>(null);
    const [presets, setPresets] = useState<string[]>(['default']);
    const [customPorts, setCustomPorts] = useState('');
    const [udp, setUdp] = useState(true);
    const portSpec = buildSpec(presets, customPorts);
    const portCount = countPorts(portSpec);
    const togglePreset = (id: string) =>
        setPresets((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));

    const fetchScans = useCallback(async () => {
        try {
            const res = await axios.get('/api/scans');
            setScans(res.data);
            setLoadError(null);
        } catch (e) {
            setLoadError(apiError(e, 'Could not load scans.'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchScans();
        const interval = setInterval(fetchScans, 5000); // keeps running scans up to date
        return () => clearInterval(interval);
    }, [fetchScans]);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        const value = target.trim();
        if (!value || portCount.error) return;

        setIsStarting(true);
        setFormError(null);
        try {
            const res = await axios.post('/api/scans', { target: value, ports: portSpec, udp });
            router.push(`/scans/${res.data.id}`);
        } catch (err) {
            setFormError(apiError(err, 'The scan could not be started.'));
            setIsStarting(false);
        }
    };

    const runningScans = scans.filter((s) => s.status === 'RUNNING');
    const completedCount = scans.filter((s) => s.status === 'COMPLETED').length;
    const totalFindings = scans.reduce((acc, s) => acc + (s._count?.findings || 0), 0);

    return (
        <div className="space-y-6">
            <PageHeader title="Scans" description="Start a discovery scan and review previous runs">
                <IconButton label="Refresh" onClick={fetchScans}>
                    <RefreshCw className="h-4 w-4" />
                </IconButton>
            </PageHeader>

            <ErrorBanner message={loadError} />

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label="Total scans" value={scans.length} icon={ListChecks} />
                <StatCard label="Running" value={runningScans.length} icon={Activity} />
                <StatCard label="Completed" value={completedCount} icon={CheckCircle2} />
                <StatCard label="Findings linked" value={totalFindings} icon={ShieldAlert} />
            </div>

            <section className="rounded-2xl border border-border bg-card p-6">
                <h2 className="text-sm font-semibold">New scan</h2>
                <p className="mt-1 text-sm text-muted-foreground">Enter a domain, an IPv4 address, or a CIDR range of /24 or smaller.</p>

                <form onSubmit={handleScan} className="mt-4 flex flex-col gap-3 md:flex-row">
                    <div className="relative flex-1">
                        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                        <input
                            type="text"
                            aria-label="Scan target"
                            placeholder="example.com, 203.0.113.10 or 203.0.113.0/24"
                            autoComplete="off"
                            spellCheck={false}
                            maxLength={253}
                            disabled={isStarting}
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            className="w-full rounded-full border border-border bg-background py-2.5 pl-10 pr-4 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-primary"
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={isStarting || !target.trim() || !!portCount.error}
                        className="flex items-center justify-center gap-2 rounded-full bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:bg-muted disabled:text-muted-foreground"
                    >
                        {isStarting ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Play className="h-4 w-4" aria-hidden />}
                        {isStarting ? 'Resolving target...' : 'Start scan'}
                    </button>
                </form>

                <fieldset className="mt-5 space-y-3" disabled={isStarting}>
                    <legend className="text-xs font-semibold text-muted-foreground">TCP ports</legend>
                    <div className="flex flex-wrap gap-2">
                        {PORT_PRESETS.map((p) => {
                            const on = presets.includes(p.id);
                            return (
                                <button
                                    key={p.id}
                                    type="button"
                                    aria-pressed={on}
                                    onClick={() => togglePreset(p.id)}
                                    title={p.id === 'default' ? `${DEFAULT_TCP_PORTS.length} common service ports` : p.spec}
                                    className={`rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${on
                                        ? 'border-primary bg-primary text-primary-foreground'
                                        : 'border-border text-muted-foreground hover:border-secondary hover:bg-accent hover:text-foreground'}`}
                                >
                                    {p.label}
                                </button>
                            );
                        })}
                    </div>
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                        <input
                            type="text"
                            aria-label="Custom ports"
                            placeholder="Custom ports, e.g. 8000-8100, 10443, 50000"
                            autoComplete="off"
                            spellCheck={false}
                            maxLength={500}
                            value={customPorts}
                            onChange={(e) => setCustomPorts(e.target.value)}
                            className="w-full rounded-full border border-border bg-background px-4 py-2 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-primary sm:flex-1"
                        />
                        <p aria-live="polite" className={`shrink-0 text-xs ${portCount.error ? 'text-sev-critical' : 'text-muted-foreground'}`}>
                            {portCount.error ?? `${portCount.count.toLocaleString('en')} TCP ${portCount.count === 1 ? 'port' : 'ports'} per host`}
                        </p>
                    </div>
                    <label className="flex items-start gap-2 text-sm">
                        <input type="checkbox" checked={udp} onChange={(e) => setUdp(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[var(--color-primary)]" />
                        <span>
                            UDP service probes
                            <span className="block text-xs text-muted-foreground">{UDP_SERVICES}. A UDP port only shows as open when the service answers a real request, so silence is not reported.</span>
                        </span>
                    </label>
                </fieldset>

                <div className="mt-4 space-y-3">
                    <ErrorBanner message={formError} />
                    <p className="flex items-start gap-2 text-xs text-muted-foreground">
                        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                        Domains include subdomain discovery. Open TCP ports get a banner grab and service checks. Large ranges on filtered hosts take longer, since each closed port waits for a timeout. Only scan systems you own or are authorised to test.
                    </p>
                </div>
            </section>

            {runningScans.length > 0 && (
                <section className="space-y-3">
                    <h2 className="text-sm font-semibold">In progress</h2>
                    {runningScans.map((scan) => {
                        const pct = scan.totalIps ? Math.round((scan.currentIndex / scan.totalIps) * 100) : 0;
                        return (
                            <Link key={scan.id} href={`/scans/${scan.id}`} className="block rounded-2xl border border-secondary bg-muted p-4 transition-colors hover:bg-accent">
                                <div className="flex items-center justify-between gap-4">
                                    <div className="flex min-w-0 items-center gap-3">
                                        <Loader2 className="h-4 w-4 shrink-0 animate-spin text-secondary" aria-hidden />
                                        <div className="min-w-0">
                                            <p className="truncate font-mono text-sm font-medium">{scan.target}</p>
                                            <p className="text-xs text-muted-foreground">{scan.currentIndex} of {scan.totalIps} IPs scanned</p>
                                        </div>
                                    </div>
                                    <div className="flex shrink-0 items-center gap-3">
                                        <div className="h-2 w-24 overflow-hidden rounded-full bg-muted sm:w-40">
                                            <div className="h-full bg-secondary transition-all duration-500" style={{ width: `${pct}%` }} />
                                        </div>
                                        <span className="w-10 text-right text-xs tabular-nums text-muted-foreground">{pct}%</span>
                                    </div>
                                </div>
                            </Link>
                        );
                    })}
                </section>
            )}

            <section className="overflow-hidden rounded-2xl border border-border bg-card">
                <div className="flex items-center justify-between border-b border-border px-6 py-4">
                    <h2 className="text-sm font-semibold">History</h2>
                    <span className="text-xs text-muted-foreground">{scans.length} {scans.length === 1 ? 'scan' : 'scans'}</span>
                </div>

                {scans.length === 0 ? (
                    <div className="px-6 py-12 text-center">
                        <ScanSearch className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" aria-hidden />
                        <p className="text-sm text-muted-foreground">{loading ? 'Loading...' : 'No scans yet. Start your first scan above.'}</p>
                    </div>
                ) : (
                    <ul className="divide-y divide-border">
                        {scans.map((scan) => (
                            <li key={scan.id}>
                                <Link href={`/scans/${scan.id}`} className="group flex items-center justify-between gap-4 px-6 py-3 transition-colors hover:bg-accent/40">
                                    <div className="min-w-0">
                                        <p className="truncate font-mono text-sm font-medium">{scan.target}</p>
                                        <p className="mt-0.5 text-xs text-muted-foreground">
                                            {scan.totalIps} {scan.totalIps === 1 ? 'IP' : 'IPs'}, {scan._count?.findings || 0} findings, {scan.type.toLowerCase()}
                                        </p>
                                    </div>
                                    <div className="flex shrink-0 items-center gap-4">
                                        <span className="hidden text-xs text-muted-foreground sm:block">{formatDateTime(scan.createdAt)}</span>
                                        <StatusBadge status={scan.status} />
                                        <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" aria-hidden />
                                    </div>
                                </Link>
                            </li>
                        ))}
                    </ul>
                )}
            </section>
        </div>
    );
}
