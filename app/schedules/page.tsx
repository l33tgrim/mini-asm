"use client";

import { useCallback, useEffect, useState } from 'react';
import { CalendarClock, CheckCircle2, Loader2, Pause, Play, Plus, RefreshCw, Target, Trash2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import axios from 'axios';
import { ErrorBanner, IconButton, PageHeader, StatCard } from '@/components/ui';
import { apiError, formatDateTime } from '@/lib/ui';

interface Schedule {
    id: string;
    target: string;
    frequency: string;
    nextRun: string;
    lastRunAt: string | null;
    active: boolean;
}

const FREQUENCIES = [
    { id: 'DAILY', label: 'Daily', detail: 'Every 24 hours' },
    { id: 'WEEKLY', label: 'Weekly', detail: 'Every 7 days' },
    { id: 'MONTHLY', label: 'Monthly', detail: 'Every 30 days' },
];

const frequencyDetail = (id: string) => FREQUENCIES.find((f) => f.id === id)?.detail ?? id;

function nextRunLabel(nextRun: string): string {
    const diff = new Date(nextRun).getTime() - Date.now();
    if (diff <= 60_000) return 'Due now';
    const hours = Math.floor(diff / 3_600_000);
    if (hours < 1) return `In ${Math.ceil(diff / 60_000)} min`;
    if (hours < 48) return `In ${hours} h`;
    return `In ${Math.floor(hours / 24)} days`;
}

export default function SchedulesPage() {
    const router = useRouter();
    const [target, setTarget] = useState('');
    const [frequency, setFrequency] = useState('DAILY');
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);
    const [busyId, setBusyId] = useState<string | null>(null);
    const [schedules, setSchedules] = useState<Schedule[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [formError, setFormError] = useState<string | null>(null);

    const fetchSchedules = useCallback(async () => {
        try {
            const res = await axios.get('/api/schedules');
            setSchedules(res.data);
            setError(null);
        } catch (e) {
            setError(apiError(e, 'Could not load schedules.'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchSchedules();
    }, [fetchSchedules]);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        const value = target.trim();
        if (!value) return;

        setCreating(true);
        setFormError(null);
        try {
            await axios.post('/api/schedules', { target: value, frequency });
            setTarget('');
            await fetchSchedules();
        } catch (err) {
            setFormError(apiError(err, 'The schedule could not be created.'));
        } finally {
            setCreating(false);
        }
    };

    // Runs one row action, reporting failure instead of pretending it worked.
    const withRow = async (id: string, failure: string, action: () => Promise<unknown>) => {
        setBusyId(id);
        setError(null);
        try {
            await action();
        } catch (e) {
            setError(apiError(e, failure));
        } finally {
            setBusyId(null);
        }
    };

    const toggle = (s: Schedule) => withRow(s.id, 'The schedule could not be updated.', async () => {
        await axios.patch(`/api/schedules/${s.id}`, { active: !s.active });
        await fetchSchedules();
    });

    const remove = (s: Schedule) => {
        if (!window.confirm(`Delete the ${s.frequency.toLowerCase()} schedule for ${s.target}?`)) return;
        return withRow(s.id, 'The schedule could not be deleted.', async () => {
            await axios.delete(`/api/schedules/${s.id}`);
            await fetchSchedules();
        });
    };

    const runNow = (s: Schedule) => withRow(s.id, `Could not start a scan of ${s.target}.`, async () => {
        const res = await axios.post('/api/scans', { target: s.target });
        router.push(`/scans/${res.data.id}`);
    });

    const activeCount = schedules.filter((s) => s.active).length;

    return (
        <div className="space-y-6">
            <PageHeader title="Schedules" description="Recurring scans that keep the inventory current">
                <IconButton label="Refresh" onClick={fetchSchedules}>
                    <RefreshCw className="h-4 w-4" />
                </IconButton>
            </PageHeader>

            <ErrorBanner message={error} />

            <div className="grid grid-cols-3 gap-4">
                <StatCard label="Schedules" value={schedules.length} icon={CalendarClock} />
                <StatCard label="Active" value={activeCount} icon={CheckCircle2} />
                <StatCard label="Paused" value={schedules.length - activeCount} icon={Pause} />
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                <section className="h-fit rounded-2xl border border-border bg-card p-6">
                    <h2 className="text-sm font-semibold">New schedule</h2>
                    <form onSubmit={handleCreate} className="mt-4 space-y-4">
                        <div>
                            <label htmlFor="schedule-target" className="mb-1.5 block text-xs font-medium text-muted-foreground">Target</label>
                            <div className="relative">
                                <Target className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                                <input
                                    id="schedule-target"
                                    type="text"
                                    placeholder="example.com or 203.0.113.0/24"
                                    autoComplete="off"
                                    spellCheck={false}
                                    maxLength={253}
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="w-full rounded-full border border-border bg-background py-2.5 pl-10 pr-4 font-mono text-sm outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-primary"
                                />
                            </div>
                        </div>

                        <fieldset>
                            <legend className="mb-1.5 text-xs font-medium text-muted-foreground">Frequency</legend>
                            <div className="grid grid-cols-3 gap-2">
                                {FREQUENCIES.map((f) => (
                                    <button
                                        key={f.id}
                                        type="button"
                                        aria-pressed={frequency === f.id}
                                        onClick={() => setFrequency(f.id)}
                                        className={`rounded-full border px-2 py-2 text-xs font-medium transition-colors ${frequency === f.id
                                            ? 'border-primary bg-primary text-white'
                                            : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground'
                                            }`}
                                    >
                                        {f.label}
                                    </button>
                                ))}
                            </div>
                        </fieldset>

                        <ErrorBanner message={formError} />

                        <button
                            type="submit"
                            disabled={creating || !target.trim()}
                            className="flex w-full items-center justify-center gap-2 rounded-full bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:bg-muted disabled:text-muted-foreground"
                        >
                            {creating ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Plus className="h-4 w-4" aria-hidden />}
                            Create schedule
                        </button>
                    </form>
                    <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
                        The first run happens one period after creation. Schedules only fire while the server is running.
                    </p>
                </section>

                <section className="overflow-hidden rounded-2xl border border-border bg-card lg:col-span-2">
                    <div className="border-b border-border px-6 py-4">
                        <h2 className="text-sm font-semibold">Configured schedules</h2>
                    </div>
                    {schedules.length === 0 ? (
                        <div className="px-6 py-12 text-center">
                            <CalendarClock className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" aria-hidden />
                            <p className="text-sm text-muted-foreground">{loading ? 'Loading...' : 'No schedules yet. Create one to scan a target automatically.'}</p>
                        </div>
                    ) : (
                        <ul className="divide-y divide-border">
                            {schedules.map((s) => (
                                <li key={s.id} className={`flex flex-wrap items-center justify-between gap-3 px-6 py-4 ${s.active ? '' : 'opacity-60'}`}>
                                    <div className="min-w-0">
                                        <p className="truncate font-mono text-sm font-medium">{s.target}</p>
                                        <p className="mt-0.5 text-xs text-muted-foreground">
                                            {frequencyDetail(s.frequency)}
                                            {s.active ? `. Next run: ${nextRunLabel(s.nextRun)}` : '. Paused'}
                                            {s.lastRunAt ? `. Last run: ${formatDateTime(s.lastRunAt)}` : ''}
                                        </p>
                                    </div>
                                    <div className="flex shrink-0 items-center gap-2">
                                        <IconButton label="Run now" onClick={() => runNow(s)} disabled={busyId !== null}>
                                            <Play className="h-4 w-4" />
                                        </IconButton>
                                        <button
                                            type="button"
                                            onClick={() => toggle(s)}
                                            disabled={busyId !== null}
                                            className="rounded-full border border-border px-3 py-2 text-xs font-medium transition-colors hover:bg-accent disabled:opacity-50"
                                        >
                                            {s.active ? 'Pause' : 'Enable'}
                                        </button>
                                        <IconButton label="Delete schedule" onClick={() => remove(s)} disabled={busyId !== null} className="hover:text-sev-critical">
                                            <Trash2 className="h-4 w-4" />
                                        </IconButton>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                </section>
            </div>
        </div>
    );
}
