"use client";

import { useCallback, useEffect, useState } from 'react';
import { ScanSearch, RefreshCw, Globe, ShieldAlert, AlertTriangle, Activity, ChevronRight } from 'lucide-react';
import axios from 'axios';
import Link from 'next/link';
import { ErrorBanner, IconButton, PageHeader, StatCard, StatusBadge } from '@/components/ui';
import { SEVERITIES, apiError, formatDateTime, severityBar, severityLabel, severityText } from '@/lib/ui';

interface Stats {
  severity: Record<string, number>;
  totalFindings: number;
  assets: number;
  runningScans: number;
  totalScans: number;
  lastDiscovery: string | null;
}

interface ScanEntry {
  id: string;
  target: string;
  status: string;
  createdAt: string;
  totalIps: number;
  _count?: { findings: number };
}

// Exposure score: each finding adds points by severity, capped at 100.
const SCORE_WEIGHTS: Record<string, number> = { CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1, INFO: 0 };

function exposure(severity: Record<string, number>) {
  const score = Math.min(100, SEVERITIES.reduce((sum, s) => sum + (severity[s] ?? 0) * SCORE_WEIGHTS[s], 0));
  if (score >= 75) return { score, label: 'Critical', level: 'CRITICAL' };
  if (score >= 50) return { score, label: 'High', level: 'HIGH' };
  if (score >= 25) return { score, label: 'Medium', level: 'MEDIUM' };
  return { score, label: 'Low', level: 'LOW' };
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, scansRes] = await Promise.all([axios.get('/api/stats'), axios.get('/api/scans')]);
      setStats(statsRes.data);
      setScans(scansRes.data);
      setError(null);
    } catch (e) {
      setError(apiError(e, 'Could not load dashboard data.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const severity = stats?.severity ?? {};
  const total = stats?.totalFindings ?? 0;
  const risk = exposure(severity);
  const largest = Math.max(1, ...SEVERITIES.map((s) => severity[s] ?? 0));
  const recentScans = scans.slice(0, 6);

  return (
    <div className="space-y-6">
      <PageHeader title="Overview" description="Current exposure across everything discovered so far">
        <IconButton label="Refresh" onClick={fetchData} disabled={loading}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        </IconButton>
        <Link href="/scans" className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90">
          <ScanSearch className="h-4 w-4" aria-hidden />
          New scan
        </Link>
      </PageHeader>

      <ErrorBanner message={error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Assets discovered" value={stats?.assets ?? 0} icon={Globe} />
        <StatCard label="Total findings" value={total} icon={ShieldAlert} />
        <StatCard label="Critical" value={severity.CRITICAL ?? 0} icon={AlertTriangle} tone={severity.CRITICAL ? 'text-sev-critical' : undefined} />
        <StatCard label="Scans running" value={stats?.runningScans ?? 0} icon={Activity} tone={stats?.runningScans ? 'text-primary' : undefined} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <section className="rounded-xl border border-border bg-card p-6">
          <h2 className="text-sm font-semibold">Exposure score</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className={`text-5xl font-semibold tabular-nums ${severityText[risk.level]}`}>{risk.score}</span>
            <span className="text-lg text-muted-foreground">/ 100</span>
          </div>
          <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-muted" role="img" aria-label={`Exposure score ${risk.score} out of 100`}>
            <div className={`h-full ${severityBar[risk.level]} transition-all duration-500`} style={{ width: `${risk.score}%` }} />
          </div>
          <p className={`mt-3 text-sm font-medium ${severityText[risk.level]}`}>{risk.label} exposure</p>
          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
            Each finding adds points by severity (critical 25, high 10, medium 3, low 1), capped at 100.
          </p>
          <p className="mt-4 border-t border-border pt-4 text-xs text-muted-foreground">
            Last discovery: {stats?.lastDiscovery ? formatDateTime(stats.lastDiscovery) : 'none yet'}
          </p>
        </section>

        <section className="rounded-xl border border-border bg-card p-6 lg:col-span-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Findings by severity</h2>
            <Link href="/findings" className="flex items-center gap-1 text-xs font-medium text-primary hover:underline">
              View findings <ChevronRight className="h-3 w-3" aria-hidden />
            </Link>
          </div>
          <div className="mt-6 space-y-4">
            {SEVERITIES.map((s) => {
              const count = severity[s] ?? 0;
              return (
                <div key={s} className="grid grid-cols-[5rem_1fr_3rem] items-center gap-3">
                  <span className="text-sm text-muted-foreground">{severityLabel(s)}</span>
                  <div className="h-2.5 overflow-hidden rounded-full bg-muted">
                    <div className={`h-full rounded-full ${severityBar[s]} transition-all duration-500`} style={{ width: `${(count / largest) * 100}%` }} />
                  </div>
                  <span className="text-right text-sm font-semibold tabular-nums">{count}</span>
                </div>
              );
            })}
          </div>
          {total === 0 && !loading && (
            <p className="mt-6 text-sm text-muted-foreground">No findings yet. Run a scan to populate this view.</p>
          )}
        </section>
      </div>

      <section className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h2 className="text-sm font-semibold">Recent scans</h2>
          <Link href="/scans" className="flex items-center gap-1 text-xs font-medium text-primary hover:underline">
            View all <ChevronRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>
        {recentScans.length === 0 ? (
          <p className="px-6 py-10 text-center text-sm text-muted-foreground">
            {loading ? 'Loading...' : 'No scans recorded yet.'}
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {recentScans.map((scan) => (
              <li key={scan.id}>
                <Link href={`/scans/${scan.id}`} className="flex items-center justify-between gap-4 px-6 py-3 transition-colors hover:bg-accent/40">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm font-medium">{scan.target}</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {scan.totalIps} {scan.totalIps === 1 ? 'IP' : 'IPs'}, {scan._count?.findings ?? 0} findings
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-4">
                    <span className="hidden text-xs text-muted-foreground sm:block">{formatDateTime(scan.createdAt)}</span>
                    <StatusBadge status={scan.status} />
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
