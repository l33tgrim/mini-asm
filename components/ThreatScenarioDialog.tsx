"use client";

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import axios from 'axios';
import { Crosshair, Loader2, Lock, X } from 'lucide-react';
import { ErrorBanner } from '@/components/ui';
import { apiError } from '@/lib/ui';
import { suggestScenarios, type AssetPort } from '@/lib/engine/applicability';
import { isTargetInScope, type ScopeKind } from '@/lib/safety/scope';

interface Engagement {
    id: string;
    name: string;
    status: string;
    mode: string;
    scope: { value: string; verified: boolean; kind?: string }[];
}
interface CatalogEntry { id: string; name: string; description: string; requiresActive: boolean }

const NEW = 'new';
const kindOf = (v: string): ScopeKind => (v.includes('/') ? 'CIDR' : /^\d{1,3}(\.\d{1,3}){3}$/.test(v) ? 'IP' : 'DOMAIN');

export function ThreatScenarioDialog({ target, ports, onClose }: { target: string; ports: AssetPort[]; onClose: () => void }) {
    const router = useRouter();
    const [engagements, setEngagements] = useState<Engagement[] | null>(null);
    const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
    const [engagementId, setEngagementId] = useState(NEW);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [running, setRunning] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const suggestions = useMemo(() => suggestScenarios({ target, ports }), [target, ports]);

    const scopeOf = (e: Engagement) => e.scope.map((s) => ({ value: s.value, verified: s.verified, kind: (s.kind as ScopeKind) || kindOf(s.value) }));
    const covers = (e: Engagement) => isTargetInScope(target, scopeOf(e));

    useEffect(() => {
        (async () => {
            try {
                const [engs, cat] = await Promise.all([axios.get('/api/engagements'), axios.get('/api/scenarios')]);
                const usable: Engagement[] = engs.data.filter((e: Engagement) => e.status !== 'REVOKED' && e.status !== 'COMPLETED');
                setEngagements(usable);
                setCatalog(cat.data.scenarios);
                const first = usable.find((e) => covers(e).inScope);
                if (first) setEngagementId(first.id);
            } catch (e) {
                setError(apiError(e, 'Could not load engagements and scenarios.'));
                setEngagements([]);
            }
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [target]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !running) onClose(); };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [onClose, running]);

    const engagement = engagements?.find((e) => e.id === engagementId);
    const inScope = engagement ? covers(engagement) : null;
    // Active proofs need an authorised ACTIVE engagement whose matching scope entry is ownership-verified.
    const activeAllowed = !!engagement && engagement.mode === 'ACTIVE' && ['AUTHORIZED', 'ACTIVE'].includes(engagement.status)
        && !!inScope?.inScope && !!inScope.matched?.verified;
    const activeHint = !engagement
        ? 'Needs an authorised engagement in ACTIVE mode. A new engagement starts in SAFE mode.'
        : engagement.mode !== 'ACTIVE' ? 'This engagement is in SAFE mode.'
            : !['AUTHORIZED', 'ACTIVE'].includes(engagement.status) ? 'Authorise the engagement first.'
                : 'The target must be ownership-verified in this engagement\'s scope.';

    const rows = suggestions
        .map((s) => ({ ...s, scenario: catalog.find((c) => c.id === s.scenarioId) }))
        .filter((r): r is typeof r & { scenario: CatalogEntry } => !!r.scenario);
    const safeRows = rows.filter((r) => !r.scenario.requiresActive);
    const activeRows = rows.filter((r) => r.scenario.requiresActive);

    // Pre-tick every scenario that can run under the chosen engagement.
    useEffect(() => {
        setSelected(new Set(rows.filter((r) => !r.scenario.requiresActive || activeAllowed).map((r) => r.scenarioId)));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [catalog, engagementId, activeAllowed]);

    const toggle = (id: string) => setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id); else next.add(id);
        return next;
    });

    const run = async () => {
        if (selected.size === 0) return;
        setRunning(true);
        setError(null);
        try {
            let id = engagementId;
            if (id === NEW) {
                id = (await axios.post('/api/engagements', { name: `${target} threat scenarios`, mode: 'SAFE' })).data.id;
            }
            if (id === NEW || !inScope?.inScope) {
                await axios.post(`/api/engagements/${id}/scope`, { values: [target] });
            }
            await axios.post(`/api/engagements/${id}/run`, { target, scenarioIds: [...selected] });
            router.push(`/engagements/${id}`);
        } catch (e) {
            setError(apiError(e, 'The scenarios could not be run.'));
            setRunning(false);
        }
    };

    const row = (r: (typeof rows)[number], disabled: boolean) => (
        <li key={r.scenarioId}>
            <label className={`flex items-start gap-3 rounded-lg p-2.5 ${disabled ? 'opacity-60' : 'cursor-pointer hover:bg-accent'}`}>
                <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 shrink-0 accent-[#1D1A60]"
                    checked={selected.has(r.scenarioId)}
                    disabled={disabled || running}
                    onChange={() => toggle(r.scenarioId)}
                />
                <span className="min-w-0">
                    <span className="block text-sm font-medium">{r.scenario.name}</span>
                    <span className="block text-xs text-muted-foreground">{r.reason}</span>
                </span>
            </label>
        </li>
    );

    return (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-primary/30 p-0 sm:items-center sm:p-4" onClick={() => !running && onClose()}>
            <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="tsd-title"
                onClick={(e) => e.stopPropagation()}
                className="flex max-h-[92vh] w-full max-w-xl flex-col overflow-hidden rounded-t-2xl border border-border bg-card shadow-xl sm:rounded-2xl"
            >
                <div className="flex items-start justify-between gap-3 border-b border-border p-5">
                    <div className="min-w-0">
                        <h2 id="tsd-title" className="flex items-center gap-2 text-base font-semibold">
                            <Crosshair className="h-4 w-4 shrink-0 text-secondary" aria-hidden /> Threat scenarios
                        </h2>
                        <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{target}</p>
                    </div>
                    <button type="button" onClick={onClose} disabled={running} aria-label="Close" className="rounded-full p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50">
                        <X className="h-4 w-4" />
                    </button>
                </div>

                <div className="space-y-5 overflow-y-auto p-5">
                    <ErrorBanner message={error} />

                    <div>
                        <label htmlFor="tsd-eng" className="mb-1 block text-xs font-semibold text-muted-foreground">Engagement</label>
                        <select
                            id="tsd-eng"
                            value={engagementId}
                            onChange={(e) => setEngagementId(e.target.value)}
                            disabled={!engagements || running}
                            className="w-full rounded-full border border-input bg-background px-3 py-2 text-sm outline-none focus:border-primary"
                        >
                            <option value={NEW}>New engagement for {target}</option>
                            {engagements?.map((e) => (
                                <option key={e.id} value={e.id}>
                                    {e.name} ({e.mode}{covers(e).inScope ? ', in scope' : ', adds target to scope'})
                                </option>
                            ))}
                        </select>
                        <p className="mt-1.5 text-xs text-muted-foreground">
                            {engagementId === NEW
                                ? 'Creates a SAFE engagement with this target in scope.'
                                : inScope?.inScope ? `In scope: ${inScope.reason.replace(/^matched /, '')}.` : 'The target will be added to this engagement\'s scope.'}
                        </p>
                    </div>

                    {!engagements ? (
                        <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Working out what applies…</p>
                    ) : (
                        <>
                            <div>
                                <p className="mb-1 text-xs font-semibold text-muted-foreground">Applies to this asset ({safeRows.length})</p>
                                <ul className="-mx-2.5">{safeRows.map((r) => row(r, false))}</ul>
                            </div>
                            {activeRows.length > 0 && (
                                <div>
                                    <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                                        <Lock className="h-3 w-3" aria-hidden /> Breach proofs, non-destructive ({activeRows.length})
                                    </p>
                                    {!activeAllowed && <p className="mb-1 text-xs text-muted-foreground">{activeHint}</p>}
                                    <ul className="-mx-2.5">{activeRows.map((r) => row(r, !activeAllowed))}</ul>
                                </div>
                            )}
                        </>
                    )}
                </div>

                <div className="flex items-center justify-between gap-3 border-t border-border p-4">
                    <p className="text-xs text-muted-foreground">{selected.size} selected</p>
                    <button
                        type="button"
                        onClick={run}
                        disabled={running || selected.size === 0 || !engagements}
                        className="flex items-center gap-2 rounded-full bg-primary px-5 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50"
                    >
                        {running ? <><Loader2 className="h-4 w-4 animate-spin" /> Running {selected.size}…</> : <><Crosshair className="h-4 w-4" /> Run scenarios</>}
                    </button>
                </div>
            </div>
        </div>
    );
}
