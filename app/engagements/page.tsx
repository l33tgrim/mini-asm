"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import axios from 'axios';
import { Shield, Plus, ChevronRight, CheckCircle2, CircleDashed, Ban } from 'lucide-react';

interface Engagement {
    id: string; name: string; description?: string; status: string; mode: string;
    authorizedBy?: string; scope: { id: string; value: string; verified: boolean }[];
    _count?: { runs: number };
}

const statusStyle: Record<string, string> = {
    DRAFT: 'text-muted-foreground bg-muted',
    AUTHORIZED: 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20',
    ACTIVE: 'text-sky-400 bg-sky-500/10 border border-sky-500/20',
    COMPLETED: 'text-primary bg-primary/10 border border-primary/20',
    REVOKED: 'text-red-400 bg-red-500/10 border border-red-500/20',
};

export default function EngagementsPage() {
    const [engagements, setEngagements] = useState<Engagement[]>([]);
    const [name, setName] = useState('');
    const [mode, setMode] = useState('SAFE');
    const [creating, setCreating] = useState(false);

    const load = () => axios.get('/api/engagements').then((r) => setEngagements(r.data)).catch(() => {});
    useEffect(() => { load(); }, []);

    const create = async () => {
        if (!name.trim()) return;
        setCreating(true);
        try {
            await axios.post('/api/engagements', { name, mode });
            setName('');
            await load();
        } finally { setCreating(false); }
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-black tracking-tight flex items-center gap-3"><Shield className="w-6 h-6 text-primary" /> Engagements</h1>
                <p className="text-sm text-muted-foreground mt-1">An authorized testing engagement. Nothing active runs without one, with verified scope.</p>
            </div>

            <div className="p-5 rounded-2xl bg-card border border-border flex flex-col sm:flex-row gap-3 sm:items-end">
                <div className="flex-1">
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Engagement name</label>
                    <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. PayInc external perimeter Q4"
                        className="w-full mt-1 bg-background border border-input rounded-xl px-3 py-2 text-sm outline-none focus:border-primary" />
                </div>
                <div>
                    <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Mode</label>
                    <select value={mode} onChange={(e) => setMode(e.target.value)} className="block mt-1 bg-background border border-input rounded-xl px-3 py-2 text-sm outline-none focus:border-primary">
                        <option value="SAFE">SAFE (recon/posture)</option>
                        <option value="ACTIVE">ACTIVE (proofs)</option>
                    </select>
                </div>
                <button onClick={create} disabled={creating} className="bg-primary text-primary-foreground rounded-xl px-4 py-2 text-sm font-bold flex items-center gap-2 disabled:opacity-50">
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
                                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${statusStyle[e.status] || ''}`}>{e.status}</span>
                                        <span className="text-[10px] px-2 py-0.5 rounded bg-muted font-bold">{e.mode}</span>
                                    </div>
                                    <p className="text-xs text-muted-foreground mt-2 flex items-center gap-3">
                                        <span>{e.scope.length} scope entries</span>
                                        <span className="flex items-center gap-1">
                                            {verified === e.scope.length && e.scope.length > 0
                                                ? <CheckCircle2 className="w-3 h-3 text-emerald-400" />
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
