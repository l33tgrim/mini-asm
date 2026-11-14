"use client";

import { useEffect, useState } from 'react';
import axios from 'axios';
import { ErrorBanner } from '@/components/ui';
import { apiError } from '@/lib/ui';
import { Zap, Shield, Target, Terminal, Layers, AlertTriangle, Hammer, Trash2, Save } from 'lucide-react';

interface Scenario {
    id: string; name: string; description: string; category: string; maxSeverity: string;
    attckTactic?: string; attckTechnique?: string; requiresActive: boolean; intrusive: boolean; tags: string[];
    params?: { key: string; label: string; type: string; help?: string }[];
}
interface Playbook { id: string; name: string; description: string; threat: string; scenarioIds: string[]; attckTactics: string[]; }
interface CustomStep { scenarioId: string; order: number; params?: string | null; }
interface CustomPlaybook { id: string; name: string; description?: string; threat?: string; steps: CustomStep[]; }
interface Cmd { key: string; command: string; purpose: string; }

const catColor: Record<string, string> = {
    RECON: 'text-foreground bg-border border-border',
    EXPOSURE: 'text-foreground bg-muted border-border',
    VULN: 'text-foreground bg-sev-critical border-sev-critical',
    WAF: 'text-foreground bg-border border-border',
    PROOF: 'text-foreground bg-sev-critical border-sev-critical',
    POSTURE: 'text-white bg-sev-medium border-sev-medium',
};

interface Picked { checked: boolean; params: string; }

export default function ScenariosPage() {
    const [scenarios, setScenarios] = useState<Scenario[]>([]);
    const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
    const [commands, setCommands] = useState<Cmd[]>([]);
    const [custom, setCustom] = useState<CustomPlaybook[]>([]);

    // Threat builder state
    const [name, setName] = useState('');
    const [threat, setThreat] = useState('');
    const [picks, setPicks] = useState<Record<string, Picked>>({});
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const loadCatalog = () => axios.get('/api/scenarios').then((r) => {
        setScenarios(r.data.scenarios); setPlaybooks(r.data.playbooks); setCommands(r.data.allowedCommands);
    }).catch(() => {});
    const loadCustom = () => axios.get('/api/playbooks').then((r) => setCustom(r.data.custom)).catch(() => {});
    useEffect(() => { loadCatalog(); loadCustom(); }, []);

    const toggle = (id: string) => setPicks((p) => ({ ...p, [id]: { checked: !p[id]?.checked, params: p[id]?.params || '' } }));
    const setParams = (id: string, v: string) => setPicks((p) => ({ ...p, [id]: { checked: p[id]?.checked ?? true, params: v } }));

    const save = async () => {
        setError(null);
        const steps = [];
        for (const s of scenarios.filter((x) => picks[x.id]?.checked)) {
            let params: unknown = undefined;
            const raw = picks[s.id]?.params?.trim();
            if (raw) {
                try { params = JSON.parse(raw); } catch { setError(`The params for "${s.name}" are not valid JSON.`); return; }
            }
            steps.push({ scenarioId: s.id, params });
        }
        if (!name.trim() || steps.length === 0) { setError('Give it a name and pick at least one scenario.'); return; }
        setSaving(true);
        try {
            await axios.post('/api/playbooks', { name, threat, steps });
            setName(''); setThreat(''); setPicks({});
            await loadCustom();
        } catch (e) {
            setError(apiError(e, 'The threat scenario could not be saved.'));
        } finally { setSaving(false); }
    };

    const del = async (id: string) => {
        if (!window.confirm('Delete this custom threat scenario?')) return;
        try { await axios.delete(`/api/playbooks/${id}`); await loadCustom(); }
        catch (e) { setError(apiError(e, 'The threat scenario could not be deleted.')); }
    };

    const selectedCount = Object.values(picks).filter((p) => p.checked).length;

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-3xl font-bold flex items-center gap-3"><Zap className="w-6 h-6 text-primary" /> Scenario Library</h1>
                <p className="text-sm text-muted-foreground mt-1">Non-destructive scenarios, threat-led playbooks, and a builder for your own modular threat scenarios.</p>
            </div>

            {/* Threat builder */}
            <section className="p-5 rounded-2xl bg-card border border-primary/20">
                <h2 className="text-xs font-bold uppercase tracking-widest text-primary mb-3 flex items-center gap-2"><Hammer className="w-4 h-4" /> Threat Builder</h2>
                <p className="text-xs text-muted-foreground mb-4">Compose scenarios into a reusable threat scenario. Add JSON params to a scenario to point it at different issues.</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
                    <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Threat scenario name (e.g. Exposed secrets sweep)"
                        className="bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary" />
                    <input value={threat} onChange={(e) => setThreat(e.target.value)} placeholder="Threat emulated (e.g. Ransomware affiliate)"
                        className="bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary" />
                </div>
                <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                    {scenarios.map((s) => {
                        const picked = picks[s.id]?.checked;
                        return (
                            <div key={s.id} className={`rounded-xl border p-3 ${picked ? 'border-primary/40 bg-primary/5' : 'border-border bg-background'}`}>
                                <label className="flex items-start gap-3 cursor-pointer">
                                    <input type="checkbox" checked={!!picked} onChange={() => toggle(s.id)} className="mt-1 accent-[color:var(--color-primary)]" />
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className="text-sm font-semibold">{s.name}</span>
                                            <span className={`text-[9px] px-1.5 py-0.5 rounded-full border font-bold ${catColor[s.category] || ''}`}>{s.category}</span>
                                            {s.requiresActive && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-sev-critical text-foreground border border-sev-critical font-bold">active</span>}
                                            {s.params && s.params.length > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-border text-foreground border border-border font-bold">parameterized</span>}
                                        </div>
                                        <p className="text-[11px] text-muted-foreground mt-1">{s.description}</p>
                                    </div>
                                </label>
                                {picked && s.params && s.params.length > 0 && (
                                    <textarea value={picks[s.id]?.params || ''} onChange={(e) => setParams(s.id, e.target.value)}
                                        placeholder={`params JSON, e.g. {"${s.params[0].key}": ...}  ${s.params[0].help || ''}`}
                                        rows={2}
                                        className="w-full mt-2 bg-background border border-input rounded-lg px-2 py-1.5 text-[11px] font-mono outline-none focus:border-primary" />
                                )}
                            </div>
                        );
                    })}
                </div>
                <div className="mt-4"><ErrorBanner message={error} /></div>
                <div className="flex items-center justify-between mt-4">
                    <span className="text-xs text-muted-foreground">{selectedCount} scenario(s) selected</span>
                    <button onClick={save} disabled={saving} className="bg-primary text-primary-foreground rounded-full px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
                        <Save className="w-4 h-4" /> {saving ? 'Saving…' : 'Save threat scenario'}
                    </button>
                </div>
            </section>

            {/* Custom playbooks */}
            {custom.length > 0 && (
                <section>
                    <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Target className="w-4 h-4" /> Your Threat Scenarios ({custom.length})</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {custom.map((p) => (
                            <div key={p.id} className="p-5 rounded-2xl bg-card border border-border">
                                <div className="flex items-center justify-between">
                                    <h3 className="font-bold">{p.name}</h3>
                                    <button onClick={() => del(p.id)} className="text-muted-foreground hover:text-foreground"><Trash2 className="w-3.5 h-3.5" /></button>
                                </div>
                                {p.threat && <p className="text-[11px] mt-1 text-foreground flex items-center gap-1.5"><Target className="w-3 h-3" /> {p.threat}</p>}
                                <div className="flex flex-wrap gap-1.5 mt-3">
                                    {p.steps.map((s) => <span key={s.scenarioId} className="text-[9px] px-2 py-0.5 rounded-full bg-muted font-mono">{s.params ? '⚙ ' : ''}{s.scenarioId}</span>)}
                                </div>
                                <p className="text-[10px] text-muted-foreground mt-3">Run it from an engagement: it appears in the run dropdown under Custom.</p>
                            </div>
                        ))}
                    </div>
                </section>
            )}

            {/* Built-in playbooks */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Layers className="w-4 h-4" /> Built-in Playbooks</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {playbooks.map((p) => (
                        <div key={p.id} className="p-5 rounded-2xl bg-card border border-border">
                            <div className="flex items-center justify-between">
                                <h3 className="font-bold">{p.name}</h3>
                                <span className="text-[10px] font-mono text-muted-foreground">{p.scenarioIds.length} steps</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-2">{p.description}</p>
                            <p className="text-[11px] mt-3 text-foreground flex items-center gap-1.5"><Target className="w-3 h-3" /> Emulates: {p.threat}</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* Scenarios */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Shield className="w-4 h-4" /> Scenarios ({scenarios.length})</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {scenarios.map((s) => (
                        <div key={s.id} className="p-5 rounded-2xl bg-card border border-border">
                            <div className="flex items-start justify-between gap-2">
                                <h3 className="font-bold text-sm">{s.name}</h3>
                                <span className={`text-[9px] px-2 py-0.5 rounded-full border font-bold ${catColor[s.category] || ''}`}>{s.category}</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-2">{s.description}</p>
                            <div className="flex items-center gap-2 mt-3 flex-wrap text-[10px]">
                                {s.requiresActive
                                    ? <span className="px-2 py-0.5 rounded-full bg-sev-critical text-foreground border border-sev-critical font-bold flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Active + verified</span>
                                    : <span className="px-2 py-0.5 rounded-full bg-sev-medium text-white border border-sev-medium font-bold">Safe</span>}
                                {s.attckTechnique && <span className="font-mono text-muted-foreground">{s.attckTechnique}</span>}
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            {/* Allowlist */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Terminal className="w-4 h-4" /> Proof-of-Command Allowlist</h2>
                <div className="rounded-2xl bg-card border border-border divide-y divide-border">
                    {commands.map((c) => (
                        <div key={c.key} className="flex items-center justify-between p-3 text-sm">
                            <code className="font-mono text-foreground">{c.command}</code>
                            <span className="text-xs text-muted-foreground">{c.purpose}</span>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
}
