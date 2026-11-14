"use client";

import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import axios from 'axios';
import { ErrorBanner, SeverityBadge } from '@/components/ui';
import { apiError } from '@/lib/ui';
import {
    Shield, Plus, CheckCircle2, CircleDashed, Play, Lock, Unlock, AlertTriangle,
    Copy, ClipboardCheck, Terminal, FileText, Trash2, Sparkles
} from 'lucide-react';

interface ScopeEntry { id: string; value: string; kind: string; verified: boolean; verifyToken?: string; verifyMethod?: string; }
interface Result { id: string; title: string; severity: string; outcome: string; attckTactic?: string; attckTechnique?: string; target?: string; evidence?: string; remediation?: string; }
interface Run { id: string; scenarioName: string; target: string; status: string; summary?: string; createdAt: string; results: Result[]; }
interface Audit { id: string; action: string; target?: string; detail?: string; actor: string; createdAt: string; }
interface Engagement { id: string; name: string; status: string; mode: string; authorizedBy?: string; scope: ScopeEntry[]; runs: Run[]; auditLogs: Audit[]; }
interface Catalog { scenarios: { id: string; name: string; requiresActive: boolean }[]; playbooks: { id: string; name: string }[]; }
interface CustomPB { id: string; name: string; }

// Outcome chips: orange for a proven exploit, Dark Blue for a confirmed weakness.
const outcomeChip: Record<string, string> = {
    PROVEN: 'bg-sev-critical text-foreground border-sev-critical',
    VULNERABLE: 'bg-primary text-white border-primary',
    SECURE: 'bg-border text-foreground border-border',
    INFO: 'bg-card text-muted-foreground border-border',
    ERROR: 'bg-card text-foreground border-sev-critical',
};
const runChip: Record<string, string> = {
    COMPLETED: 'bg-sev-medium text-white',
    BLOCKED: 'bg-sev-critical text-foreground',
    FAILED: 'bg-sev-critical text-foreground',
};
const chip = 'rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide';

export default function EngagementDetail() {
    const { id } = useParams<{ id: string }>();
    const [eng, setEng] = useState<Engagement | null>(null);
    const [catalog, setCatalog] = useState<Catalog | null>(null);
    const [customPlaybooks, setCustomPlaybooks] = useState<CustomPB[]>([]);
    const [scopeInput, setScopeInput] = useState('');
    const [selection, setSelection] = useState('');
    const [target, setTarget] = useState('');
    const [busy, setBusy] = useState('');
    const [copied, setCopied] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [missing, setMissing] = useState(false);
    const [ai, setAi] = useState<{ risk: { score: number; grade: string; headline: string }; narrative: string; plannedBy: string } | null>(null);

    const load = useCallback(() => axios.get(`/api/engagements/${id}`).then((r) => setEng(r.data)).catch((e) => {
        if (axios.isAxiosError(e) && e.response?.status === 404) setMissing(true);
        else setError(apiError(e, 'Could not load this engagement.'));
    }), [id]);

    // Runs one action, clears the busy flag and reports any failure in the page.
    const act = async (key: string, failure: string, fn: () => Promise<unknown>) => {
        setBusy(key);
        setError(null);
        try { await fn(); } catch (e) { setError(apiError(e, failure)); } finally { setBusy(''); }
    };
    useEffect(() => {
        load();
        axios.get('/api/scenarios').then((r) => setCatalog(r.data)).catch(() => {});
        axios.get('/api/playbooks').then((r) => setCustomPlaybooks(r.data.custom)).catch(() => {});
    }, [load]);

    const addScope = () => {
        const values = scopeInput.split(',').map((v) => v.trim()).filter(Boolean);
        if (values.length === 0) return;
        return act('scope', 'The scope could not be added.', async () => {
            await axios.post(`/api/engagements/${id}/scope`, { values });
            setScopeInput('');
            await load();
        });
    };
    const removeScope = (entryId: string) => act('scope', 'The scope entry could not be removed.', async () => {
        await axios.delete(`/api/engagements/${id}/scope?entryId=${entryId}`);
        await load();
    });
    const verify = () => act('verify', 'Ownership could not be checked.', async () => {
        await axios.post(`/api/engagements/${id}/verify`);
        await load();
    });
    const authorize = () => act('auth', 'The engagement could not be authorised.', async () => {
        try {
            await axios.post(`/api/engagements/${id}/authorize`, { by: 'PayInc operator' });
        } catch (e) {
            const domains = axios.isAxiosError(e) ? (e.response?.data?.domains as string[] | undefined) : undefined;
            if (!domains) throw e;
            if (!window.confirm(`These domains are not ownership-verified:\n${domains.join('\n')}\n\nAuthorise anyway by operator attestation? This is recorded in the audit trail.`)) return;
            await axios.post(`/api/engagements/${id}/authorize`, { by: 'PayInc operator', force: true });
        }
        await load();
    });
    const revoke = () => {
        if (!window.confirm('Revoke authorisation? Active scenarios will be blocked.')) return;
        return act('auth', 'The authorisation could not be revoked.', async () => {
            await axios.delete(`/api/engagements/${id}/authorize`);
            await load();
        });
    };

    const run = () => {
        if (!selection || !target.trim()) { setError('Choose a scenario or playbook and enter a target that is in scope.'); return; }
        return act('run', 'The run failed.', async () => {
            const [kind, realId] = selection.split(':');
            const body = kind === 'playbook' ? { playbookId: realId, target }
                : kind === 'custom' ? { customPlaybookId: realId, target }
                    : { scenarioId: realId, target };
            await axios.post(`/api/engagements/${id}/run`, body);
            await load();
        });
    };

    const autorun = () => {
        if (!target.trim()) { setError('Enter a target that is in scope first.'); return; }
        return act('ai', 'The assessment failed.', async () => {
            const res = await axios.post(`/api/engagements/${id}/autorun`, { target });
            setAi(res.data);
            await load();
        });
    };

    const copyToken = (t: string, key: string) => { navigator.clipboard.writeText(t); setCopied(key); setTimeout(() => setCopied(''), 1500); };

    if (missing) return <p className="py-24 text-center text-sm text-muted-foreground">This engagement does not exist.</p>;
    if (!eng) return error ? <ErrorBanner message={error} /> : <div className="text-sm text-muted-foreground">Loading engagement…</div>;
    const authorized = eng.status === 'AUTHORIZED' || eng.status === 'ACTIVE';

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3"><Shield className="w-6 h-6 text-primary" /> {eng.name}</h1>
                    <div className="flex items-center gap-2 mt-2">
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted font-bold">{eng.status}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted font-bold">{eng.mode} mode</span>
                        {eng.authorizedBy && <span className="text-[10px] text-muted-foreground">by {eng.authorizedBy}</span>}
                    </div>
                </div>
                {authorized
                    ? <button onClick={revoke} disabled={busy === 'auth'} className="text-sm font-semibold px-5 py-2 rounded-full border border-sev-critical text-foreground hover:bg-accent flex items-center gap-2 disabled:opacity-50"><Lock className="w-4 h-4" /> Revoke</button>
                    : <button onClick={authorize} disabled={busy === 'auth'} className="text-sm font-semibold px-5 py-2 rounded-full bg-primary text-white flex items-center gap-2 disabled:opacity-50"><Unlock className="w-4 h-4" /> Authorize</button>}
            </div>

            <ErrorBanner message={error} />

            {/* Scope */}
            <section className="p-5 rounded-2xl bg-card border border-border">
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Scope</h2>
                    <button onClick={verify} disabled={busy === 'verify'} className="text-xs font-bold px-3 py-1.5 rounded-full bg-primary/10 text-primary border border-primary/20 flex items-center gap-1.5 disabled:opacity-50">
                        <ClipboardCheck className="w-3.5 h-3.5" /> {busy === 'verify' ? 'Checking…' : 'Verify ownership'}
                    </button>
                </div>
                <div className="flex gap-2 mb-3">
                    <input value={scopeInput} onChange={(e) => setScopeInput(e.target.value)} placeholder="domain, IP, or CIDR (comma-separated)"
                        className="flex-1 bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary" />
                    <button onClick={addScope} disabled={busy === 'scope'} className="bg-primary text-primary-foreground rounded-full px-3 py-2 text-sm font-bold flex items-center gap-1.5 disabled:opacity-50"><Plus className="w-4 h-4" /> Add</button>
                </div>
                <div className="space-y-2">
                    {eng.scope.map((s) => (
                        <div key={s.id} className="p-3 rounded-xl bg-background border border-border">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    {s.verified ? <CheckCircle2 className="w-4 h-4 text-foreground" /> : <CircleDashed className="w-4 h-4 text-muted-foreground" />}
                                    <code className="text-sm font-mono">{s.value}</code>
                                    <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-muted font-bold">{s.kind}</span>
                                    {s.verified && <span className="text-[9px] text-foreground">{s.verifyMethod}</span>}
                                </div>
                                <button onClick={() => removeScope(s.id)} className="text-muted-foreground hover:text-foreground"><Trash2 className="w-3.5 h-3.5" /></button>
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
                    <select value={selection} onChange={(e) => setSelection(e.target.value)} className="flex-1 bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary">
                        <option value="">Select…</option>
                        {catalog && (
                            <>
                                <optgroup label="Playbooks">
                                    {catalog.playbooks.map((p) => <option key={p.id} value={`playbook:${p.id}`}>▶ {p.name}</option>)}
                                </optgroup>
                                {customPlaybooks.length > 0 && (
                                    <optgroup label="Custom threat scenarios">
                                        {customPlaybooks.map((p) => <option key={p.id} value={`custom:${p.id}`}>★ {p.name}</option>)}
                                    </optgroup>
                                )}
                                <optgroup label="Scenarios">
                                    {catalog.scenarios.map((s) => <option key={s.id} value={`scenario:${s.id}`}>{s.requiresActive ? '● ' : '○ '}{s.name}</option>)}
                                </optgroup>
                            </>
                        )}
                    </select>
                    <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="target (must be in scope)"
                        className="flex-1 bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary" />
                    <button onClick={run} disabled={busy === 'run'} className="bg-primary text-primary-foreground rounded-full px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
                        <Play className="w-4 h-4" /> {busy === 'run' ? 'Running…' : 'Run'}
                    </button>
                    <button onClick={autorun} disabled={busy === 'ai'} title="Autonomous: recon, adaptive scenario plan, scoring, narrative"
                        className="border border-secondary text-foreground hover:bg-accent rounded-full px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
                        <Sparkles className="w-4 h-4" /> {busy === 'ai' ? 'Assessing…' : 'AI assessment'}
                    </button>
                </div>
                <p className="text-[11px] text-muted-foreground mt-2 flex items-center gap-1.5"><AlertTriangle className="w-3 h-3" /> ● = active (needs authorized + verified scope). ○ = safe. AI assessment plans its own scenario chain and respects the same gates.</p>
            </section>

            {ai && (
                <section className="p-5 rounded-2xl bg-card border border-primary/30">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                        <h2 className="text-xs font-bold uppercase tracking-widest text-primary flex items-center gap-2"><Sparkles className="w-4 h-4" /> AI Assessment</h2>
                        <div className="flex items-center gap-3">
                            <span className="text-[10px] text-muted-foreground">planned by {ai.plannedBy}</span>
                            <span className="text-lg font-bold">{ai.risk.grade} · {ai.risk.score}/100</span>
                        </div>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{ai.risk.headline}</p>
                    <pre className="text-[12px] mt-3 whitespace-pre-wrap text-foreground/90 bg-background/50 rounded-lg p-3 leading-relaxed">{ai.narrative}</pre>
                </section>
            )}

            {/* Results */}
            <section>
                <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3 flex items-center gap-2"><FileText className="w-4 h-4" /> Results</h2>
                <div className="space-y-3">
                    {eng.runs.map((r) => (
                        <div key={r.id} className="p-4 rounded-2xl bg-card border border-border">
                            <div className="flex items-center justify-between">
                                <h3 className="font-bold text-sm">{r.scenarioName} <span className="text-muted-foreground font-normal">→ {r.target}</span></h3>
                                <span className={`${chip} border-transparent ${runChip[r.status] || 'bg-muted text-foreground'}`}>{r.status}</span>
                            </div>
                            {r.summary && <p className="text-xs text-muted-foreground mt-1">{r.summary}</p>}
                            <div className="mt-3 space-y-2">
                                {r.results.map((f) => (
                                    <div key={f.id} className="p-3 rounded-lg border border-border bg-background">
                                        <div className="flex items-center justify-between gap-2">
                                            <span className="text-sm font-semibold">{f.title}</span>
                                            <span className="flex shrink-0 items-center gap-1.5">
                                                <SeverityBadge severity={f.severity} />
                                                <span className={`${chip} ${outcomeChip[f.outcome] || outcomeChip.INFO}`}>{f.outcome}</span>
                                            </span>
                                        </div>
                                        {f.attckTechnique && <p className="text-[10px] font-mono text-muted-foreground mt-1">{f.attckTactic} / {f.attckTechnique}</p>}
                                        {f.evidence && <pre className="text-[11px] mt-2 whitespace-pre-wrap text-foreground/80 font-mono bg-background/50 rounded p-2 overflow-x-auto">{f.evidence}</pre>}
                                        {f.remediation && <p className="text-[11px] mt-2 text-foreground">Fix: {f.remediation}</p>}
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
                            <span className="font-semibold">{a.action}</span>
                            <span className="text-muted-foreground truncate">{a.target} {a.detail}</span>
                        </div>
                    ))}
                    {eng.auditLogs.length === 0 && <p className="p-3 text-xs text-muted-foreground">No audit entries yet.</p>}
                </div>
            </section>
        </div>
    );
}
