"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import axios from 'axios';
import { ShieldCheck, Activity, Target, Crosshair, ArrowRight, Zap, FileText } from 'lucide-react';

interface Dash {
    engagementCount: number;
    runCount: number;
    scenarioCount: number;
    posture: { score: number; grade: string; proven: number; vulnerable: number; headline: string };
    severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
    attack: { tested: string[]; catalog: string[]; coveragePct: number };
    recent: { id: string; engagementId: string; engagement?: string; scenario: string; target: string; status: string; results: number; createdAt: string }[];
}

const gradeColor: Record<string, string> = { A: 'text-emerald-400', B: 'text-teal-400', C: 'text-amber-400', D: 'text-orange-400', F: 'text-red-400' };
const sev = [
    { key: 'CRITICAL', label: 'Critical', cls: 'text-red-400 border-red-500/30 bg-red-500/5' },
    { key: 'HIGH', label: 'High', cls: 'text-orange-400 border-orange-500/30 bg-orange-500/5' },
    { key: 'MEDIUM', label: 'Medium', cls: 'text-amber-400 border-amber-500/30 bg-amber-500/5' },
    { key: 'LOW', label: 'Low', cls: 'text-sky-400 border-sky-500/30 bg-sky-500/5' },
] as const;

export default function Dashboard() {
    const [d, setD] = useState<Dash | null>(null);
    useEffect(() => { axios.get('/api/dashboard').then((r) => setD(r.data)).catch(() => {}); }, []);

    if (!d) return <div className="text-sm text-muted-foreground">Loading…</div>;
    const ring = d.posture.score;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-black tracking-tight">Security Validation</h1>
                    <p className="text-sm text-muted-foreground mt-1">Continuous breach & attack simulation across PayInc assets. Authorized testing only.</p>
                </div>
                <Link href="/engagements" className="brand-gradient text-white rounded-xl px-4 py-2 text-sm font-bold flex items-center gap-2">
                    New engagement <ArrowRight className="w-4 h-4" />
                </Link>
            </div>

            {/* Posture + stats */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                <div className="lg:col-span-1 p-5 rounded-2xl bg-card border border-border flex items-center gap-5">
                    <div className="relative w-24 h-24 shrink-0">
                        <svg viewBox="0 0 100 100" className="w-24 h-24 -rotate-90">
                            <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="8" className="text-muted" />
                            <circle cx="50" cy="50" r="42" fill="none" stroke="url(#g)" strokeWidth="8" strokeLinecap="round"
                                strokeDasharray={`${(ring / 100) * 264} 264`} />
                            <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="hsl(214 84% 54%)" /><stop offset="1" stopColor="hsl(172 66% 42%)" /></linearGradient></defs>
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className={`text-2xl font-black ${gradeColor[d.posture.grade]}`}>{d.posture.grade}</span>
                            <span className="text-[10px] text-muted-foreground">{d.posture.score}/100</span>
                        </div>
                    </div>
                    <div>
                        <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Posture</p>
                        <p className="text-sm font-semibold mt-1">{d.posture.headline}</p>
                        <p className="text-[11px] text-muted-foreground mt-1">{d.posture.proven} proven · {d.posture.vulnerable} unproven</p>
                    </div>
                </div>

                <StatTile icon={<Target className="w-4 h-4" />} label="Engagements" value={d.engagementCount} />
                <StatTile icon={<Activity className="w-4 h-4" />} label="Scenario runs" value={d.runCount} />
                <StatTile icon={<Zap className="w-4 h-4" />} label="Scenarios available" value={d.scenarioCount} />
            </div>

            {/* Severity */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {sev.map((s) => (
                    <div key={s.key} className={`p-4 rounded-2xl border ${s.cls}`}>
                        <p className="text-3xl font-black">{d.severity[s.key]}</p>
                        <p className="text-[11px] font-bold uppercase tracking-widest mt-1">{s.label}</p>
                    </div>
                ))}
            </div>

            {/* ATT&CK coverage */}
            <div className="p-5 rounded-2xl bg-card border border-border">
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground flex items-center gap-2"><Crosshair className="w-4 h-4" /> MITRE ATT&CK coverage</h2>
                    <span className="text-sm font-black">{d.attack.coveragePct}%</span>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden mb-3">
                    <div className="h-full brand-gradient" style={{ width: `${d.attack.coveragePct}%` }} />
                </div>
                <div className="flex flex-wrap gap-1.5">
                    {d.attack.catalog.map((t) => {
                        const tested = d.attack.tested.includes(t);
                        return <span key={t} className={`text-[10px] px-2 py-0.5 rounded border font-bold ${tested ? 'text-teal-400 border-teal-500/30 bg-teal-500/5' : 'text-muted-foreground border-border bg-muted/40'}`}>{t}</span>;
                    })}
                </div>
            </div>

            {/* Recent */}
            <div>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><FileText className="w-4 h-4" /> Recent activity</h2>
                <div className="rounded-2xl bg-card border border-border divide-y divide-border">
                    {d.recent.map((r) => (
                        <Link key={r.id} href={`/engagements/${r.engagementId}`} className="flex items-center justify-between p-3 hover:bg-accent/40 transition-colors">
                            <div className="min-w-0">
                                <p className="text-sm font-semibold truncate">{r.scenario} <span className="text-muted-foreground font-normal">→ {r.target}</span></p>
                                <p className="text-[11px] text-muted-foreground truncate">{r.engagement} · {r.results} result(s)</p>
                            </div>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold shrink-0 ${r.status === 'BLOCKED' ? 'bg-red-500/10 text-red-400' : r.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-muted'}`}>{r.status}</span>
                        </Link>
                    ))}
                    {d.recent.length === 0 && (
                        <div className="p-8 text-center text-sm text-muted-foreground">
                            No activity yet. <Link href="/engagements" className="text-primary font-semibold">Create an engagement</Link> to start.
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function StatTile({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
    return (
        <div className="p-5 rounded-2xl bg-card border border-border">
            <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">{icon} {label}</p>
            <p className="text-3xl font-black mt-2">{value}</p>
        </div>
    );
}
