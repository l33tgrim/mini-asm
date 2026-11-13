"use client";

import { useEffect, useState } from 'react';
import axios from 'axios';
import { Zap, Shield, Target, Terminal, Layers, AlertTriangle } from 'lucide-react';

interface Scenario {
    id: string; name: string; description: string; category: string; maxSeverity: string;
    attckTactic?: string; attckTechnique?: string; requiresActive: boolean; intrusive: boolean; tags: string[];
}
interface Playbook { id: string; name: string; description: string; threat: string; scenarioIds: string[]; attckTactics: string[]; }
interface Cmd { key: string; command: string; purpose: string; }

const catColor: Record<string, string> = {
    RECON: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
    EXPOSURE: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    VULN: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    WAF: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    PROOF: 'text-red-400 bg-red-500/10 border-red-500/20',
    POSTURE: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
};

export default function ScenariosPage() {
    const [scenarios, setScenarios] = useState<Scenario[]>([]);
    const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
    const [commands, setCommands] = useState<Cmd[]>([]);

    useEffect(() => {
        axios.get('/api/scenarios').then((r) => {
            setScenarios(r.data.scenarios);
            setPlaybooks(r.data.playbooks);
            setCommands(r.data.allowedCommands);
        }).catch(() => {});
    }, []);

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-black tracking-tight flex items-center gap-3"><Zap className="w-6 h-6 text-primary" /> Scenario Library</h1>
                <p className="text-sm text-muted-foreground mt-1">Non-destructive breach-simulation scenarios and threat-led playbooks. Active scenarios run only against authorized, verified scope.</p>
            </div>

            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Layers className="w-4 h-4" /> Threat-Led Playbooks</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {playbooks.map((p) => (
                        <div key={p.id} className="p-5 rounded-2xl bg-card border border-border">
                            <div className="flex items-center justify-between">
                                <h3 className="font-bold">{p.name}</h3>
                                <span className="text-[10px] font-mono text-muted-foreground">{p.scenarioIds.length} steps</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-2">{p.description}</p>
                            <p className="text-[11px] mt-3 text-amber-400/90 flex items-center gap-1.5"><Target className="w-3 h-3" /> Emulates: {p.threat}</p>
                            <div className="flex flex-wrap gap-1.5 mt-3">
                                {p.scenarioIds.map((s) => <span key={s} className="text-[9px] px-2 py-0.5 rounded bg-muted font-mono">{s}</span>)}
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Shield className="w-4 h-4" /> Scenarios ({scenarios.length})</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {scenarios.map((s) => (
                        <div key={s.id} className="p-5 rounded-2xl bg-card border border-border">
                            <div className="flex items-start justify-between gap-2">
                                <h3 className="font-bold text-sm">{s.name}</h3>
                                <span className={`text-[9px] px-2 py-0.5 rounded border font-bold ${catColor[s.category] || ''}`}>{s.category}</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-2">{s.description}</p>
                            <div className="flex items-center gap-2 mt-3 flex-wrap text-[10px]">
                                {s.requiresActive
                                    ? <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Active + verified</span>
                                    : <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">Safe</span>}
                                {s.attckTechnique && <span className="font-mono text-muted-foreground">{s.attckTechnique}</span>}
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Terminal className="w-4 h-4" /> Proof-of-Command Allowlist</h2>
                <p className="text-xs text-muted-foreground mb-3">The only commands a proof scenario may ever execute. Benign, read-only, enforced in code.</p>
                <div className="rounded-2xl bg-card border border-border divide-y divide-border">
                    {commands.map((c) => (
                        <div key={c.key} className="flex items-center justify-between p-3 text-sm">
                            <code className="font-mono text-emerald-400">{c.command}</code>
                            <span className="text-xs text-muted-foreground">{c.purpose}</span>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
}
