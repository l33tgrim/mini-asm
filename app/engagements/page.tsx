"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import axios from 'axios';
import { ErrorBanner } from '@/components/ui';
import { apiError } from '@/lib/ui';
import { Shield, Plus, ChevronRight, CheckCircle2, CircleDashed, Ban } from 'lucide-react';

interface Engagement {
    id: string; name: string; description?: string; status: string; mode: string;
    authorizedBy?: string; scope: { id: string; value: string; verified: boolean }[];
    _count?: { runs: number };
}

const statusStyle: Record<string, string> = {
    DRAFT: 'text-muted-foreground bg-muted',
    AUTHORIZED: 'text-white bg-sev-medium border border-sev-medium',
    ACTIVE: 'text-foreground bg-border border border-border',
    COMPLETED: 'text-primary bg-primary/10 border border-primary/20',
    REVOKED: 'text-foreground bg-sev-critical border border-sev-critical',
};

export default function EngagementsPage() {
    const [engagements, setEngagements] = useState<Engagement[]>([]);
    const [name, setName] = useState('');
    const [mode, setMode] = useState('SAFE');
    const [creating, setCreating] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const load = () => axios.get('/api/engagements').then((r) => setEngagements(r.data)).catch((e) => setError(apiError(e, 'Could not load engagements.')));
    useEffect(() => { load(); }, []);

    const create = async () => {
        if (!name.trim()) return;
        setCreating(true);
        setError(null);
        try {
            await axios.post('/api/engagements', { name, mode });
            setName('');
            await load();
        } catch (e) {
            setError(apiError(e, 'The engagement could not be created.'));
        } finally { setCreating(false); }
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold flex items-center gap-3"><Shield className="w-6 h-6 text-primary" /> Engagements</h1>
                <p className="text-sm text-muted-foreground mt-1">An authorized testing engagement. Nothing active runs without one, with verified scope.</p>
            </div>

            <ErrorBanner message={error} />

            <div className="p-5 rounded-2xl bg-card border border-border flex flex-col sm:flex-row gap-3 sm:items-end">
                <div className="flex-1">
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Engagement name</label>
                    <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. PayInc external perimeter Q4"
                        className="w-full mt-1 bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary" />
                </div>
                <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Mode</label>
                    <select value={mode} onChange={(e) => setMode(e.target.value)} className="block mt-1 bg-background border border-input rounded-full px-3 py-2 text-sm outline-none focus:border-primary">
                        <option value="SAFE">SAFE (recon/posture)</option>
                        <option value="ACTIVE">ACTIVE (proofs)</option>
                    </select>
                </div>
                <button onClick={create} disabled={creating} className="bg-primary text-primary-foreground rounded-full px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
                    <Plus className="w-4 h-4" /> Create
                </button>
            </div>

            <div className="space-y-3">
                {engagements.map((e) => {
                    const verified = e.scope.filter((s) => s.verified).length;
                    return (
                        <Link key={e.id} href={`/engagements/${e.id}`} className="block p-5 rounded-2xl bg-card border border-border hover:border-primary/40 transition-colors">
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="flex items-center gap-3">
                                        <h3 className="font-bold">{e.name}</h3>
                                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${statusStyle[e.status] || ''}`}>{e.status}</span>
                                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted font-bold">{e.mode}</span>
                                    </div>
                                    <p className="text-xs text-muted-foreground mt-2 flex items-center gap-3">
                                        <span>{e.scope.length} scope entries</span>
                                        <span className="flex items-center gap-1">
                                            {verified === e.scope.length && e.scope.length > 0
                                                ? <CheckCircle2 className="w-3 h-3 text-foreground" />
                                                : <CircleDashed className="w-3 h-3" />}
                                            {verified}/{e.scope.length} verified
                                        </span>
                                        <span>{e._count?.runs ?? 0} runs</span>
                                        {e.authorizedBy && <span>authorized by {e.authorizedBy}</span>}
                                    </p>
                                </div>
                                <ChevronRight className="w-4 h-4 text-muted-foreground" />
                            </div>
                        </Link>
                    );
                })}
                {engagements.length === 0 && (
                    <div className="p-10 rounded-2xl bg-card border border-border border-dashed text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                        <Ban className="w-5 h-5" /> No engagements yet. Create one to begin authorized testing.
                    </div>
                )}
            </div>
        </div>
    );
}
