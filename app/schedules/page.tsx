"use client";

import { useState, useEffect } from 'react';
import {
    Calendar, Clock, Plus, Trash2, ToggleLeft, ToggleRight, Target,
    RefreshCw, Play, AlertTriangle, CheckCircle2, Timer, Repeat,
    CalendarClock, Zap, ChevronRight, History, Settings2
} from 'lucide-react';
import axios from 'axios';

interface Schedule {
    id: string;
    target: string;
    frequency: string;
    nextRun: string;
    active: boolean;
    createdAt?: string;
    lastRun?: string;
}

export default function SchedulesPage() {
    const [target, setTarget] = useState('');
    const [frequency, setFrequency] = useState('DAILY');
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);
    const [schedules, setSchedules] = useState<Schedule[]>([]);

    const fetchSchedules = async () => {
        try {
            const res = await axios.get('/api/schedules');
            setSchedules(res.data);
        } catch (error) {
            console.error('Failed to fetch schedules', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSchedules();
    }, []);

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) return;

        setCreating(true);
        try {
            await axios.post('/api/schedules', { target, frequency });
            setTarget('');
            fetchSchedules();
        } catch (error) {
            console.error('Failed to create schedule', error);
        } finally {
            setCreating(false);
        }
    };

    const handleToggle = async (id: string, currentActive: boolean) => {
        try {
            await axios.patch(`/api/schedules/${id}`, { active: !currentActive });
            fetchSchedules();
        } catch (error) {
            console.error('Failed to toggle schedule', error);
            // Optimistic update fallback
            setSchedules(schedules.map(s =>
                s.id === id ? { ...s, active: !s.active } : s
            ));
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Are you sure you want to delete this schedule?')) return;
        try {
            await axios.delete(`/api/schedules/${id}`);
            fetchSchedules();
        } catch (error) {
            console.error('Failed to delete schedule', error);
        }
    };

    const handleRunNow = async (target: string) => {
        try {
            await axios.post('/api/scans', { target });
            alert(`Scan started for ${target}`);
        } catch (error) {
            console.error('Failed to run scan', error);
        }
    };

    const activeSchedules = schedules.filter(s => s.active);
    const inactiveSchedules = schedules.filter(s => !s.active);

    const getFrequencyLabel = (freq: string) => {
        switch (freq) {
            case 'DAILY': return 'Every 24 Hours';
            case 'WEEKLY': return 'Every 7 Days';
            case 'MONTHLY': return 'Every 30 Days';
            default: return freq;
        }
    };

    const getNextRunStatus = (nextRun: string) => {
        const next = new Date(nextRun);
        const now = new Date();
        const diff = next.getTime() - now.getTime();
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const days = Math.floor(hours / 24);

        if (diff < 0) return { label: 'Overdue', color: 'text-red-500', urgent: true };
        if (hours < 1) return { label: 'Soon', color: 'text-yellow-500', urgent: true };
        if (hours < 24) return { label: `In ${hours}h`, color: 'text-blue-500', urgent: false };
        return { label: `In ${days}d`, color: 'text-muted-foreground', urgent: false };
    };

    return (
        <div className="space-y-6 animate-in fade-in duration-700">
            {/* Header */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-black tracking-tight">Automated Scan Schedules</h1>
                    <p className="text-muted-foreground mt-1">Configure recurring attack surface monitoring</p>
                </div>
                <button
                    onClick={fetchSchedules}
                    className="self-start p-2 rounded-xl border border-border hover:bg-accent transition-all"
                >
                    <RefreshCw className="w-4 h-4" />
                </button>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10"><CalendarClock className="w-5 h-5 text-primary" /></div>
                        <div>
                            <p className="text-2xl font-black">{schedules.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Total Schedules</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-green-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-green-500/10"><CheckCircle2 className="w-5 h-5 text-green-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-green-500">{activeSchedules.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Active</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/10"><Repeat className="w-5 h-5 text-blue-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{schedules.filter(s => s.frequency === 'DAILY').length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Daily</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10"><Timer className="w-5 h-5 text-purple-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{schedules.filter(s => s.frequency === 'WEEKLY').length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Weekly</p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Create Schedule Form */}
                <div className="lg:col-span-1">
                    <div className="bg-gradient-to-br from-card to-primary/5 border border-primary/20 rounded-2xl p-6 sticky top-6">
                        <div className="flex items-center gap-3 mb-6">
                            <div className="p-2 rounded-xl bg-primary/20">
                                <Plus className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <h3 className="font-bold">New Schedule</h3>
                                <p className="text-xs text-muted-foreground">Automate recurring scans</p>
                            </div>
                        </div>

                        <form onSubmit={handleCreate} className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-muted-foreground uppercase tracking-widest">Target</label>
                                <div className="relative">
                                    <Target className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground w-4 h-4" />
                                    <input
                                        type="text"
                                        placeholder="e.g. example.com or 10.0.0.0/24"
                                        value={target}
                                        onChange={(e) => setTarget(e.target.value)}
                                        className="w-full bg-background/50 border border-border rounded-xl py-3 pl-10 pr-4 focus:ring-2 focus:ring-primary outline-none transition-all font-mono text-sm"
                                    />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <label className="text-xs font-bold text-muted-foreground uppercase tracking-widest">Frequency</label>
                                <div className="grid grid-cols-3 gap-2">
                                    {[
                                        { id: 'DAILY', label: '24h', icon: Zap },
                                        { id: 'WEEKLY', label: '7d', icon: Calendar },
                                        { id: 'MONTHLY', label: '30d', icon: CalendarClock },
                                    ].map((freq) => (
                                        <button
                                            key={freq.id}
                                            type="button"
                                            onClick={() => setFrequency(freq.id)}
                                            className={`p-3 rounded-xl border transition-all text-center ${frequency === freq.id
                                                ? 'border-primary bg-primary/10 text-primary'
                                                : 'border-border hover:border-primary/30'
                                                }`}
                                        >
                                            <freq.icon className="w-4 h-4 mx-auto mb-1" />
                                            <p className="text-xs font-bold">{freq.label}</p>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={creating || !target}
                                className={`w-full py-3 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${creating || !target
                                    ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                    : 'bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20'
                                    }`}
                            >
                                {creating ? (
                                    <>
                                        <RefreshCw className="w-4 h-4 animate-spin" />
                                        Creating...
                                    </>
                                ) : (
                                    <>
                                        <Plus className="w-4 h-4" />
                                        Create Schedule
                                    </>
                                )}
                            </button>
                        </form>

                        {/* Quick Info */}
                        <div className="mt-4 p-3 bg-muted/30 rounded-xl">
                            <p className="text-[10px] text-muted-foreground">
                                <strong className="text-foreground">Note:</strong> Schedules run automatically at the configured interval.
                                You can trigger an immediate scan using the play button.
                            </p>
                        </div>
                    </div>
                </div>

                {/* Schedule List */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Active Schedules */}
                    {activeSchedules.length > 0 && (
                        <div>
                            <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-widest mb-3 flex items-center gap-2">
                                <CheckCircle2 className="w-4 h-4 text-green-500" />
                                Active Schedules
                            </h3>
                            <div className="space-y-3">
                                {activeSchedules.map((schedule) => {
                                    const nextStatus = getNextRunStatus(schedule.nextRun);
                                    return (
                                        <div
                                            key={schedule.id}
                                            className="bg-card border border-green-500/20 rounded-xl p-4 hover:border-green-500/40 transition-all"
                                        >
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-4">
                                                    <div className="p-3 rounded-xl bg-green-500/10">
                                                        <Calendar className="w-5 h-5 text-green-500" />
                                                    </div>
                                                    <div>
                                                        <p className="font-mono font-bold">{schedule.target}</p>
                                                        <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                                                            <span className="flex items-center gap-1">
                                                                <Repeat className="w-3 h-3" />
                                                                {getFrequencyLabel(schedule.frequency)}
                                                            </span>
                                                            <span>•</span>
                                                            <span className={`flex items-center gap-1 ${nextStatus.color}`}>
                                                                <Clock className="w-3 h-3" />
                                                                {nextStatus.label}
                                                            </span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={() => handleRunNow(schedule.target)}
                                                        className="p-2 rounded-lg hover:bg-primary/10 text-muted-foreground hover:text-primary transition-all"
                                                        title="Run Now"
                                                    >
                                                        <Play className="w-4 h-4" />
                                                    </button>
                                                    <button
                                                        onClick={() => handleToggle(schedule.id, schedule.active)}
                                                        className="p-2 rounded-lg hover:bg-accent transition-all"
                                                        title="Toggle"
                                                    >
                                                        <ToggleRight className="w-6 h-6 text-green-500" />
                                                    </button>
                                                    <button
                                                        onClick={() => handleDelete(schedule.id)}
                                                        className="p-2 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-500 transition-all"
                                                        title="Delete"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* Inactive Schedules */}
                    {inactiveSchedules.length > 0 && (
                        <div>
                            <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-widest mb-3 flex items-center gap-2">
                                <ToggleLeft className="w-4 h-4" />
                                Paused Schedules
                            </h3>
                            <div className="space-y-3">
                                {inactiveSchedules.map((schedule) => (
                                    <div
                                        key={schedule.id}
                                        className="bg-card border border-border rounded-xl p-4 opacity-60 hover:opacity-100 transition-all"
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-4">
                                                <div className="p-3 rounded-xl bg-muted">
                                                    <Calendar className="w-5 h-5 text-muted-foreground" />
                                                </div>
                                                <div>
                                                    <p className="font-mono font-bold text-muted-foreground">{schedule.target}</p>
                                                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                                                        <span className="flex items-center gap-1">
                                                            <Repeat className="w-3 h-3" />
                                                            {getFrequencyLabel(schedule.frequency)}
                                                        </span>
                                                        <span>•</span>
                                                        <span className="text-yellow-500">Paused</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => handleToggle(schedule.id, schedule.active)}
                                                    className="p-2 rounded-lg hover:bg-accent transition-all"
                                                    title="Enable"
                                                >
                                                    <ToggleLeft className="w-6 h-6 text-muted-foreground" />
                                                </button>
                                                <button
                                                    onClick={() => handleDelete(schedule.id)}
                                                    className="p-2 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-500 transition-all"
                                                    title="Delete"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Empty State */}
                    {schedules.length === 0 && !loading && (
                        <div className="bg-card border border-border rounded-2xl p-12 text-center">
                            <CalendarClock className="w-12 h-12 mx-auto text-muted-foreground/30 mb-4" />
                            <h3 className="font-bold mb-2">No Schedules Configured</h3>
                            <p className="text-sm text-muted-foreground">
                                Create your first automated scan schedule to continuously monitor your attack surface.
                            </p>
                        </div>
                    )}

                    {/* Info Card */}
                    <div className="bg-gradient-to-r from-blue-500/5 to-purple-500/5 border border-blue-500/20 rounded-xl p-4">
                        <div className="flex items-start gap-3">
                            <div className="p-2 rounded-lg bg-blue-500/10 shrink-0">
                                <Settings2 className="w-4 h-4 text-blue-500" />
                            </div>
                            <div>
                                <p className="text-sm font-bold text-blue-400">Continuous Monitoring</p>
                                <p className="text-xs text-muted-foreground mt-1">
                                    Scheduled scans automatically discover new assets, detect changes, and identify emerging vulnerabilities.
                                    Results are aggregated in your Attack Surface inventory.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
