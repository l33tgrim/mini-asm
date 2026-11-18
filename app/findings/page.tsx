"use client";

import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Download, RefreshCw, Search, Server, ShieldCheck, Flame, ListChecks } from 'lucide-react';
import axios from 'axios';
import { type Finding } from '@/components/FindingCard';
import FindingGroupCard from '@/components/FindingGroupCard';
import { groupFindings } from '@/lib/group-findings';
import { ErrorBanner, IconButton, PageHeader, StatCard } from '@/components/ui';
import { SEVERITIES, SEVERITY_RANK, apiError, portLabel } from '@/lib/ui';

const PAGE_SIZE = 30;

// Cells that start with a formula character are neutralised so a hostile banner
// cannot execute when the export is opened in a spreadsheet.
function csvCell(value: unknown): string {
    let text = value === null || value === undefined ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
}

function exportCsv(findings: Finding[]) {
    const columns: (keyof Finding)[] = ['severity', 'ip', 'port', 'protocol', 'service', 'version', 'domains', 'vulnerability', 'remediation', 'description', 'techStack', 'updatedAt'];
    const rows = [columns.join(','), ...findings.map((f) => columns.map((c) => csvCell(f[c])).join(','))];
    const url = URL.createObjectURL(new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `findings-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
}

export default function FindingsPage() {
    const [findings, setFindings] = useState<Finding[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState<string>('ALL');
    const [searchQuery, setSearchQuery] = useState('');
    const [visible, setVisible] = useState(PAGE_SIZE);

    const fetchFindings = useCallback(async () => {
        setLoading(true);
        try {
            const res = await axios.get('/api/findings');
            // 0.0.0.0 holds the DNS reconnaissance summary, shown on the attack surface page instead.
            setFindings((res.data as Finding[]).filter((f) => f.ip !== '0.0.0.0'));
            setError(null);
        } catch (e) {
            setError(apiError(e, 'Could not load findings.'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchFindings();
    }, [fetchFindings]);

    const filtered = useMemo(() => {
        const q = searchQuery.trim().toLowerCase();
        return findings
            .filter((f) => filter === 'ALL' || f.severity === filter)
            .filter((f) => !q || [f.ip, String(f.port), portLabel(f.port, f.protocol), f.service, f.domains, f.vulnerability].some((v) => v?.toLowerCase().includes(q)))
            .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
    }, [findings, filter, searchQuery]);

    const groups = useMemo(() => groupFindings(filtered), [filtered]);
    const allGroups = useMemo(() => groupFindings(findings), [findings]);
    const count = (s: string) => allGroups.filter((g) => g.severity === s).length;
    const critical = count('CRITICAL');
    const high = count('HIGH');

    return (
        <div className="space-y-6">
            <PageHeader title="Findings" description="Every exposed service and the issues detected on it">
                <IconButton label="Refresh" onClick={fetchFindings} disabled={loading}>
                    <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                </IconButton>
                <button
                    type="button"
                    onClick={() => exportCsv(filtered)}
                    disabled={filtered.length === 0}
                    className="flex items-center gap-2 rounded-full border border-border px-3 py-2 text-sm font-medium transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                >
                    <Download className="h-4 w-4" aria-hidden />
                    Export CSV
                </button>
            </PageHeader>

            <ErrorBanner message={error} />

            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label="Findings" value={allGroups.length} icon={ListChecks} />
                <StatCard label="Critical" value={critical} icon={AlertTriangle} />
                <StatCard label="High" value={high} icon={Flame} />
                <StatCard label="Hosts affected" value={new Set(findings.map((f) => f.ip)).size} icon={Server} />
            </div>

            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
                <div className="relative flex-1 lg:max-w-md">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                    <input
                        type="search"
                        aria-label="Search findings"
                        placeholder="Search by IP, port, service, domain or issue"
                        value={searchQuery}
                        onChange={(e) => { setSearchQuery(e.target.value); setVisible(PAGE_SIZE); }}
                        className="w-full rounded-full border border-border bg-card py-2 pl-10 pr-4 text-sm outline-none transition-colors focus:border-primary"
                    />
                </div>
                <div role="group" aria-label="Filter by severity" className="flex flex-wrap items-center gap-1 rounded-full border border-border bg-card p-1">
                    {['ALL', ...SEVERITIES].map((s) => (
                        <button
                            key={s}
                            type="button"
                            aria-pressed={filter === s}
                            onClick={() => { setFilter(s); setVisible(PAGE_SIZE); }}
                            className={`rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${filter === s ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent hover:text-foreground'}`}
                        >
                            {s === 'ALL' ? 'All' : s.charAt(0) + s.slice(1).toLowerCase()}
                        </button>
                    ))}
                </div>
            </div>

            <div className="space-y-3">
                {loading && findings.length === 0 ? (
                    <p className="rounded-2xl border border-border bg-card p-12 text-center text-sm text-muted-foreground">Loading findings...</p>
                ) : groups.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-border bg-card p-12 text-center">
                        <ShieldCheck className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" aria-hidden />
                        <p className="text-sm font-medium">No findings to show</p>
                        <p className="mt-1 text-sm text-muted-foreground">
                            {findings.length === 0 ? 'Run a scan to discover exposed services.' : 'Try a different search or severity filter.'}
                        </p>
                    </div>
                ) : (
                    groups.slice(0, visible).map((group) => <FindingGroupCard key={group.key} group={group} />)
                )}
            </div>

            {groups.length > 0 && (
                <div className="flex flex-col items-center gap-3">
                    <p className="text-xs text-muted-foreground">
                        Showing {Math.min(visible, groups.length)} of {groups.length} findings across {filtered.length} host and port entries
                    </p>
                    {visible < groups.length && (
                        <button type="button" onClick={() => setVisible(visible + PAGE_SIZE)} className="rounded-full border border-border px-4 py-2 text-sm font-medium transition-colors hover:bg-accent">
                            Show more
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}
