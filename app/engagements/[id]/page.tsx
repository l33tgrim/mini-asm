"use client";

import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import axios from 'axios';
import {
    Shield, Plus, CheckCircle2, CircleDashed, Play, Lock, Unlock, AlertTriangle,
    Copy, ClipboardCheck, Terminal, FileText, Trash2
} from 'lucide-react';

interface ScopeEntry { id: string; value: string; kind: string; verified: boolean; verifyToken?: string; verifyMethod?: string; }
interface Result { id: string; title: string; severity: string; outcome: string; attckTactic?: string; attckTechnique?: string; target?: string; evidence?: string; remediation?: string; }
interface Run { id: string; scenarioName: string; target: string; status: string; summary?: string; createdAt: string; results: Result[]; }
interface Audit { id: string; action: string; target?: string; detail?: string; actor: string; createdAt: string; }
interface Engagement { id: string; name: string; status: string; mode: string; authorizedBy?: string; scope: ScopeEntry[]; runs: Run[]; auditLogs: Audit[]; }
interface Catalog { scenarios: { id: string; name: string; requiresActive: boolean }[]; playbooks: { id: string; name: string }[]; }

const sevColor: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW: 'text-sky-400 bg-sky-500/10 border-sky-500/30',
    INFO: 'text-muted-foreground bg-muted border-border',
};
const outcomeColor: Record<string, string> = {
    PROVEN: 'text-red-400', VULNERABLE: 'text-orange-400', SECURE: 'text-emerald-400', INFO: 'text-muted-foreground', ERROR: 'text-red-400',
};

export default function EngagementDetail() {
    const { id } = useParams<{ id: string }>();
    const [eng, setEng] = useState<Engagement | null>(null);
    const [catalog, setCatalog] = useState<Catalog | null>(null);
    const [scopeInput, setScopeInput] = useState('');
    const [selection, setSelection] = useState('');
    const [target, setTarget] = useState('');
    const [busy, setBusy] = useState('');
    const [copied, setCopied] = useState('');

    const load = useCallback(() => axios.get(`/api/engagements/${id}`).then((r) => setEng(r.data)).catch(() => {}), [id]);
    useEffect(() => {
        load();
        axios.get('/api/scenarios').then((r) => setCatalog(r.data)).catch(() => {});
    }, [load]);

    const addScope = async () => {
        if (!scopeInput.trim()) return;
        setBusy('scope');
        try {
            await axios.post(`/api/engagements/${id}/scope`, { values: scopeInput.split(',').map((s) => s.trim()).filter(Boolean) });
            setScopeInput('');
            await load();
        } finally { setBusy(''); }
    };
    const removeScope = async (entryId: string) => { await axios.delete(`/api/engagements/${id}/scope?entryId=${entryId}`); await load(); };
    const verify = async () => { setBusy('verify'); try { await axios.post(`/api/engagements/${id}/verify`); await load(); } finally { setBusy(''); } };
    const authorize = async (force = false) => {
        setBusy('auth');
        try { await axios.post(`/api/engagements/${id}/authorize`, { by: 'PayInc operator', force }); await load(); }
        catch (e) {
            const err = (e as { response?: { data?: { domains?: string[] } } }).response;
            if (err?.data?.domains && confirm(`These domains are not ownership-verified:\n${err.data.domains.join('\n')}\n\nAuthorize anyway by operator attestation?`)) {
                await axios.post(`/api/engagements/${id}/authorize`, { by: 'PayInc operator', force: true });
                await load();
            }
        } finally { setBusy(''); }
    };
    const revoke = async () => { if (confirm('Revoke authorization? Active scenarios will be blocked.')) { await axios.delete(`/api/engagements/${id}/authorize`); await load(); } };

    const run = async () => {
        if (!selection || !target.trim()) return;
        setBusy('run');
        try {
            const [kind, realId] = selection.split(':');
            const body = kind === 'playbook' ? { playbookId: realId, target } : { scenarioId: realId, target };
            await axios.post(`/api/engagements/${id}/run`, body);
            await load();
        } catch (e) {
            alert('Run failed: ' + (e as { response?: { data?: { error?: string } } }).response?.data?.error);
        } finally { setBusy(''); }
    };

    const copyToken = (t: string, key: string) => { navigator.clipboard.writeText(t); setCopied(key); setTimeout(() => setCopied(''), 1500); };

    if (!eng) return <div className="text-sm text-muted-foreground">Loading engagement…</div>;
    const authorized = eng.status === 'AUTHORIZED' || eng.status === 'ACTIVE';

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-black tracking-tight flex items-center gap-3"><Shield className="w-6 h-6 text-primary" /> {eng.name}</h1>
                    <div className="flex items-center gap-2 mt-2">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-muted font-bold">{eng.status}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-muted font-bold">{eng.mode} mode</span>
                        {eng.authorizedBy && <span className="text-[10px] text-muted-foreground">by {eng.authorizedBy}</span>}
                    </div>
                </div>
                {authorized
                    ? <button onClick={revoke} className="text-sm font-bold px-4 py-2 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20 flex items-center gap-2"><Lock className="w-4 h-4" /> Revoke</button>
                    : <button onClick={() => authorize(false)} disabled={busy === 'auth'} className="text-sm font-bold px-4 py-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-2 disabled:opacity-50"><Unlock className="w-4 h-4" /> Authorize</button>}
            </div>

            {/* Scope */}
            <section className="p-5 rounded-2xl bg-card border border-border">
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Scope</h2>
                    <button onClick={verify} disabled={busy === 'verify'} className="text-xs font-bold px-3 py-1.5 rounded-lg bg-primary/10 text-primary border border-primary/20 flex items-center gap-1.5 disabled:opacity-50">
                        <ClipboardCheck className="w-3.5 h-3.5" /> {busy === 'verify' ? 'Checking…' : 'Verify ownership'}
                    </button>
                </div>
                <div className="flex gap-2 mb-3">
                    <input value={scopeInput} onChange={(e) => setScopeInput(e.target.value)} placeholder="domain, IP, or CIDR (comma-separated)"
                        className="flex-1 bg-background border border-input rounded-xl px-3 py-2 text-sm outline-none focus:border-primary" />
                    <button onClick={addScope} disabled={busy === 'scope'} className="bg-primary text-primary-foreground rounded-xl px-3 py-2 text-sm font-bold flex items-center gap-1.5 disabled:opacity-50"><Plus className="w-4 h-4" /> Add</button>
                </div>
                <div className="space-y-2">
                    {eng.scope.map((s) => (
                        <div key={s.id} className="p-3 rounded-xl bg-background border border-border">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    {s.verified ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <CircleDashed className="w-4 h-4 text-muted-foreground" />}
                                    <code className="text-sm font-mono">{s.value}</code>
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-muted font-bold">{s.kind}</span>
                                    {s.verified && <span className="text-[9px] text-emerald-400">{s.verifyMethod}</span>}
                                </div>
                                <button onClick={() => removeScope(s.id)} className="text-muted-foreground hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
                            </div>
                            {!s.verified && s.kind === 'DOMAIN' && s.verifyToken && (
                                <div className="mt-2 text-[11px] text-muted-foreground bg-muted/40 rounded-lg p-2 font-mono break-all">
                                    <div className="flex items-center justify-between gap-2">
                                        <span>TXT _miniasm-auth.{s.value} = {s.verifyToken}</span>
                                        <button onClick={() => copyToken(s.verifyToken!, s.id)} className="shrink-0 text-primary">{copied === s.id ? <ClipboardCheck className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}</button>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                    {eng.scope.length === 0 && <p className="text-xs text-muted-foreground">No scope yet. Add the assets you are authorized to test.</p>}
                </div>
            </section>

            {/* Run */}
            <section className="p-5 rounded-2xl bg-card border border-border">
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Run a scenario or playbook</h2>
                <div className="flex flex-col sm:flex-row gap-2">
                    <select value={selection} onChange={(e) => setSelection(e.target.value)} className="flex-1 bg-background border border-input rounded-xl px-3 py-2 text-sm outline-none focus:border-primary">
                        <option value="">Select…</option>
                        {catalog && (
                            <>
                                <optgroup label="Playbooks">
                                    {catalog.playbooks.map((p) => <option key={p.id} value={`playbook:${p.id}`}>▶ {p.name}</option>)}
                                </optgroup>
                                <optgroup label="Scenarios">
                                    {catalog.scenarios.map((s) => <option key={s.id} value={`scenario:${s.id}`}>{s.requiresActive ? '● ' : '○ '}{s.name}</option>)}
                                </optgroup>
                            </>
                        )}
                    </select>
                    <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="target (must be in scope)"
                        className="flex-1 bg-background border border-input rounded-xl px-3 py-2 text-sm outline-none focus:border-primary" />
                    <button onClick={run} disabled={busy === 'run'} className="bg-primary text-primary-foreground rounded-xl px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
                        <Play className="w-4 h-4" /> {busy === 'run' ? 'Running…' : 'Run'}
                    </button>
                </div>
                <p className="text-[11px] text-muted-foreground mt-2 flex items-center gap-1.5"><AlertTriangle className="w-3 h-3" /> ● = active (needs authorized + verified scope). ○ = safe.</p>
            </section>

            {/* Results */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><FileText className="w-4 h-4" /> Results</h2>
                <div className="space-y-3">
                    {eng.runs.map((r) => (
                        <div key={r.id} className="p-4 rounded-2xl bg-card border border-border">
                            <div className="flex items-center justify-between">
                                <h3 className="font-bold text-sm">{r.scenarioName} <span className="text-muted-foreground font-normal">→ {r.target}</span></h3>
                                <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${r.status === 'BLOCKED' ? 'bg-red-500/10 text-red-400' : r.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-muted'}`}>{r.status}</span>
                            </div>
                            {r.summary && <p className="text-xs text-muted-foreground mt-1">{r.summary}</p>}
                            <div className="mt-3 space-y-2">
                                {r.results.map((f) => (
                                    <div key={f.id} className={`p-3 rounded-xl border ${sevColor[f.severity] || ''}`}>
                                        <div className="flex items-center justify-between gap-2">
                                            <span className="text-sm font-semibold">{f.title}</span>
                                            <span className={`text-[10px] font-black ${outcomeColor[f.outcome] || ''}`}>{f.outcome}</span>
                                        </div>
                                        {f.attckTechnique && <p className="text-[10px] font-mono text-muted-foreground mt-1">{f.attckTactic} / {f.attckTechnique}</p>}
                                        {f.evidence && <pre className="text-[11px] mt-2 whitespace-pre-wrap text-foreground/80 font-mono bg-background/50 rounded p-2 overflow-x-auto">{f.evidence}</pre>}
                                        {f.remediation && <p className="text-[11px] mt-2 text-emerald-400/90">Fix: {f.remediation}</p>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                    {eng.runs.length === 0 && <p className="text-xs text-muted-foreground">No runs yet.</p>}
                </div>
            </section>

            {/* Audit */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><Terminal className="w-4 h-4" /> Audit trail</h2>
                <div className="rounded-2xl bg-card border border-border divide-y divide-border max-h-80 overflow-y-auto">
                    {eng.auditLogs.map((a) => (
                        <div key={a.id} className="p-2.5 text-[11px] font-mono flex items-center gap-3">
                            <span className="text-muted-foreground shrink-0">{new Date(a.createdAt).toLocaleTimeString()}</span>
                            <span className={`font-bold ${a.action.includes('BLOCKED') || a.action.includes('FAILED') ? 'text-red-400' : a.action.includes('AUTHORIZED') || a.action.includes('VERIFIED') ? 'text-emerald-400' : 'text-sky-400'}`}>{a.action}</span>
                            <span className="text-muted-foreground truncate">{a.target} {a.detail}</span>
                        </div>
                    ))}
                    {eng.auditLogs.length === 0 && <p className="p-3 text-xs text-muted-foreground">No audit entries yet.</p>}
                </div>
            </section>
        </div>
    );
}
