"use client";

import { useCallback, useEffect, useState } from 'react';
import { Activity, ArrowRight, ChevronRight, Crosshair, Globe, RefreshCw, ShieldAlert, Target } from 'lucide-react';
import axios from 'axios';
import Link from 'next/link';
import { ErrorBanner, IconButton, PageHeader, StatCard, StatusBadge } from '@/components/ui';
import { SEVERITIES, apiError, formatDateTime, severityBar, severityLabel } from '@/lib/ui';

interface Dash {
  engagementCount: number;
  runCount: number;
  scenarioCount: number;
  posture: { score: number; grade: string; proven: number; vulnerable: number; headline: string };
  severity: Record<string, number>;
  attack: { tested: string[]; catalog: string[]; coveragePct: number };
  recent: { id: string; engagementId: string; engagement?: string; scenario: string; target: string; status: string; results: number }[];
}

interface Stats {
  severity: Record<string, number>;
  totalFindings: number;
  assets: number;
  runningScans: number;
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

const linkClass = 'flex items-center gap-1 text-xs font-medium text-foreground underline decoration-secondary decoration-2 underline-offset-4 hover:decoration-foreground';
const runChip: Record<string, string> = { COMPLETED: 'bg-sev-medium text-white', BLOCKED: 'bg-sev-critical text-foreground', FAILED: 'bg-sev-critical text-foreground' };

function SeverityBars({ counts, levels }: { counts: Record<string, number>; levels: readonly string[] }) {
  const largest = Math.max(1, ...levels.map((s) => counts[s] ?? 0));
  return (
    <div className="mt-5 space-y-3.5">
      {levels.map((s) => (
        <div key={s} className="grid grid-cols-[4.5rem_1fr_2.5rem] items-center gap-3">
          <span className="text-sm text-muted-foreground">{severityLabel(s)}</span>
          <div className="h-2.5 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${severityBar[s]} transition-all duration-500`} style={{ width: `${((counts[s] ?? 0) / largest) * 100}%` }} />
          </div>
          <span className="text-right text-sm font-semibold tabular-nums">{counts[s] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [dash, setDash] = useState<Dash | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [dashRes, statsRes, scansRes] = await Promise.all([axios.get('/api/dashboard'), axios.get('/api/stats'), axios.get('/api/scans')]);
      setDash(dashRes.data);
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

  const posture = dash?.posture;
  const tested = dash && dash.runCount > 0;

  return (
    <div className="space-y-6">
      <PageHeader title="Security validation" description="Breach and attack simulation and attack surface, for authorised PayInc assets">
        <IconButton label="Refresh" onClick={fetchData} disabled={loading}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        </IconButton>
        <Link href="/engagements" className="flex items-center gap-2 rounded-full bg-primary px-5 py-2 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90">
          New engagement <ArrowRight className="h-4 w-4" aria-hidden />
        </Link>
      </PageHeader>

      <ErrorBanner message={error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Engagements" value={dash?.engagementCount ?? 0} icon={Target} />
        <StatCard label="Scenario runs" value={dash?.runCount ?? 0} icon={Activity} />
        <StatCard label="Assets discovered" value={stats?.assets ?? 0} icon={Globe} />
        <StatCard label="Scan findings" value={stats?.totalFindings ?? 0} icon={ShieldAlert} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <section className="rounded-2xl border border-border bg-card p-6">
          <h2 className="text-sm font-semibold">Posture</h2>
          <div className="mt-4 flex items-center gap-5">
            <div className="relative h-28 w-28 shrink-0" role="img" aria-label={tested ? `Posture score ${posture?.score} out of 100, grade ${posture?.grade}` : 'No posture score yet'}>
              <svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90">
                <circle cx="50" cy="50" r="42" fill="none" stroke="var(--color-muted)" strokeWidth="9" />
                {tested && (
                  <circle cx="50" cy="50" r="42" fill="none" stroke="var(--color-secondary)" strokeWidth="9" strokeLinecap="round" strokeDasharray={`${((posture?.score ?? 0) / 100) * 264} 264`} />
                )}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold">{tested ? posture?.grade : '–'}</span>
                <span className="text-xs text-muted-foreground">{tested ? `${posture?.score}/100` : 'not tested'}</span>
              </div>
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium">{tested ? posture?.headline : 'Run a scenario to get a score'}</p>
              {tested && <p className="mt-1 text-xs text-muted-foreground">{posture?.proven} proven, {posture?.vulnerable} unproven</p>}
            </div>
          </div>
          <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
            100 is clean. The score falls as simulations confirm weaknesses, and a proven exploit weighs more than an unproven one.
          </p>
        </section>

        <section className="rounded-2xl border border-border bg-card p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Simulation results</h2>
            <Link href="/engagements" className={linkClass}>Engagements <ChevronRight className="h-3 w-3" aria-hidden /></Link>
          </div>
          <SeverityBars counts={dash?.severity ?? {}} levels={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']} />
          <p className="mt-4 text-xs text-muted-foreground">Weaknesses confirmed or proven by scenario runs.</p>
        </section>

        <section className="rounded-2xl border border-border bg-card p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Attack surface findings</h2>
            <Link href="/findings" className={linkClass}>Findings <ChevronRight className="h-3 w-3" aria-hidden /></Link>
          </div>
          <SeverityBars counts={stats?.severity ?? {}} levels={SEVERITIES} />
          <p className="mt-4 text-xs text-muted-foreground">
            Exposed services from scans. Last discovery: {stats?.lastDiscovery ? formatDateTime(stats.lastDiscovery) : 'none yet'}.
          </p>
        </section>
      </div>

      <section className="rounded-2xl border border-border bg-card p-6">
        <div className="flex items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><Crosshair className="h-4 w-4" aria-hidden /> MITRE ATT&amp;CK tactic coverage</h2>
          <span className="text-sm font-semibold tabular-nums">{dash?.attack.coveragePct ?? 0}%</span>
        </div>
        <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-muted">
          <div className="h-full rounded-full bg-secondary transition-all duration-500" style={{ width: `${dash?.attack.coveragePct ?? 0}%` }} />
        </div>
        <div className="mt-4 flex flex-wrap gap-1.5">
          {(dash?.attack.catalog ?? []).map((t) => {
            const done = dash?.attack.tested.includes(t);
            return (
              <span key={t} className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${done ? 'border-primary bg-primary text-white' : 'border-border bg-card text-muted-foreground'}`}>
                {t}
              </span>
            );
          })}
        </div>
        <p className="mt-3 text-xs text-muted-foreground">Filled tactics have been exercised by at least one scenario run.</p>
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="overflow-hidden rounded-2xl border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-6 py-4">
            <h2 className="text-sm font-semibold">Recent simulation runs</h2>
            <Link href="/engagements" className={linkClass}>View all <ChevronRight className="h-3 w-3" aria-hidden /></Link>
          </div>
          {!dash || dash.recent.length === 0 ? (
            <p className="px-6 py-10 text-center text-sm text-muted-foreground">{loading ? 'Loading...' : 'No runs yet. Create an engagement to start.'}</p>
          ) : (
            <ul className="divide-y divide-border">
              {dash.recent.map((r) => (
                <li key={r.id}>
                  <Link href={`/engagements/${r.engagementId}`} className="flex items-center justify-between gap-4 px-6 py-3 transition-colors hover:bg-accent/40">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{r.scenario}</p>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">{r.target}, {r.engagement}, {r.results} {r.results === 1 ? 'result' : 'results'}</p>
                    </div>
                    <span className={`shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${runChip[r.status] ?? 'bg-muted text-foreground'}`}>{r.status}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="overflow-hidden rounded-2xl border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-6 py-4">
            <h2 className="text-sm font-semibold">Recent scans</h2>
            <Link href="/scans" className={linkClass}>View all <ChevronRight className="h-3 w-3" aria-hidden /></Link>
          </div>
          {scans.length === 0 ? (
            <p className="px-6 py-10 text-center text-sm text-muted-foreground">{loading ? 'Loading...' : 'No scans recorded yet.'}</p>
          ) : (
            <ul className="divide-y divide-border">
              {scans.slice(0, 6).map((scan) => (
                <li key={scan.id}>
                  <Link href={`/scans/${scan.id}`} className="flex items-center justify-between gap-4 px-6 py-3 transition-colors hover:bg-accent/40">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{scan.target}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">{scan.totalIps} {scan.totalIps === 1 ? 'IP' : 'IPs'}, {scan._count?.findings ?? 0} findings, {formatDateTime(scan.createdAt)}</p>
                    </div>
                    <StatusBadge status={scan.status} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
