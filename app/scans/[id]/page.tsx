"use client";

import { useEffect, useState, use, useRef } from 'react';
import {
    ShieldAlert, Globe, Server, AlertTriangle, ShieldCheck,
    ArrowLeft, Clock, Target, Activity, Search, RefreshCw,
    Terminal, Eye, Code, ChevronDown, ChevronUp, Play, Pause,
    CheckCircle2, AlertCircle, Timer
} from 'lucide-react';
import Link from 'next/link';
import axios from 'axios';

interface Finding {
    id: string;
    ip: string;
    port: number;
    service: string | null;
    version: string | null;
    banner: string | null;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    description: string | null;
    vulnerability: string | null;
    remediation: string | null;
    forensics: string | null;
    upstreamVersion: string | null;
    domains: string | null;
    techStack: string | null;
}

interface Scan {
    id: string;
    target: string;
    status: string;
    type: string;
    currentIndex: number;
    totalIps: number;
    startedAt: string | null;
    completedAt: string | null;
    createdAt: string;
    findings: Finding[];
}

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const [scan, setScan] = useState<Scan | null>(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');
    const [isActionLoading, setIsActionLoading] = useState(false);
    const [expandedForensics, setExpandedForensics] = useState<Set<string>>(new Set());
    const [elapsedTime, setElapsedTime] = useState(0);
    const timerRef = useRef<NodeJS.Timeout | null>(null);

    const toggleForensics = (fid: string) => {
        const next = new Set(expandedForensics);
        if (next.has(fid)) next.delete(fid);
        else next.add(fid);
        setExpandedForensics(next);
    };

    const toHex = (str: string) => {
        return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    };

    const handleAction = async (action: 'START' | 'RESUME') => {
        if (!scan) return;
        setIsActionLoading(true);
        try {
            const payload = action === 'START' ? { target: scan.target } : { resumeId: scan.id };
            const res = await axios.post('/api/scans', payload);
            if (action === 'START') {
                window.location.href = `/scans/${res.data.id}`;
            } else {
                fetchScan(); // Just refresh local state for resume
            }
        } catch (error) {
            alert(`Failed to ${action.toLowerCase()} scan.`);
        } finally {
            setIsActionLoading(false);
        }
    };

    const fetchScan = async () => {
        try {
            const res = await axios.get(`/api/scans/${id}`);
            setScan(res.data);

            // Calculate elapsed time if running
            if (res.data.status === 'RUNNING' && res.data.startedAt) {
                const start = new Date(res.data.startedAt).getTime();
                setElapsedTime(Math.floor((Date.now() - start) / 1000));
            } else if (res.data.status === 'COMPLETED' && res.data.startedAt && res.data.completedAt) {
                const start = new Date(res.data.startedAt).getTime();
                const end = new Date(res.data.completedAt).getTime();
                setElapsedTime(Math.floor((end - start) / 1000));
            }
        } catch (error) {
            console.error('Failed to fetch scan', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScan();
        const poll = setInterval(fetchScan, 3000);
        return () => clearInterval(poll);
    }, [id]);

    useEffect(() => {
        if (scan?.status === 'RUNNING') {
            timerRef.current = setInterval(() => {
                setElapsedTime(prev => prev + 1);
            }, 1000);
        } else {
            if (timerRef.current) clearInterval(timerRef.current);
        }
        return () => { if (timerRef.current) clearInterval(timerRef.current); };
    }, [scan?.status]);

    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <Activity className="w-10 h-10 animate-spin text-primary" />
            </div>
        );
    }

    if (!scan) return <div>Scan not found</div>;

    const filteredFindings = scan.findings.filter(f =>
        f.ip.includes(filter) ||
        f.service?.toLowerCase().includes(filter.toLowerCase()) ||
        f.description?.toLowerCase().includes(filter.toLowerCase())
    );

    const severityColors: Record<string, string> = {
        CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/20',
        HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
        MEDIUM: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
        LOW: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
        INFO: 'text-zinc-500 bg-zinc-500/10 border-zinc-500/20',
    };

    const progress = scan.totalIps > 0 ? (scan.currentIndex / scan.totalIps) * 100 : 0;

    // ETA Calculation
    const calculateETA = () => {
        if (!scan.startedAt || scan.currentIndex === 0 || scan.status !== 'RUNNING') return null;
        const start = new Date(scan.startedAt).getTime();
        const elapsed = Date.now() - start;
        const avgTimePerIp = elapsed / scan.currentIndex;
        const remainingIps = scan.totalIps - scan.currentIndex;
        const remainingMs = avgTimePerIp * remainingIps;
        return formatTime(Math.ceil(remainingMs / 1000));
    };

    const eta = calculateETA();

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex items-center gap-4">
                    <Link href="/scans" className="p-2 hover:bg-accent rounded-xl transition-colors">
                        <ArrowLeft className="w-6 h-6" />
                    </Link>
                    <div>
                        <div className="flex items-center gap-3">
                            <h2 className="text-3xl font-bold tracking-tight">{scan.target}</h2>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-black tracking-widest uppercase ${scan.status === 'COMPLETED' ? 'bg-green-500/10 text-green-500 border border-green-500/20' :
                                scan.status === 'RUNNING' ? 'bg-blue-500/10 text-blue-500 border border-blue-500/20 animate-pulse' :
                                    scan.status === 'TIMED_OUT' ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20' :
                                        'bg-zinc-500/10 text-zinc-500 border border-zinc-500/20'
                                }`}>
                                {scan.status}
                            </span>
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1.5 font-medium"><Clock className="w-4 h-4" /> {new Date(scan.createdAt).toLocaleString()}</span>
                            <span className="flex items-center gap-1.5 font-medium"><Target className="w-4 h-4" /> {scan.type} Discovery</span>
                            <span className="flex items-center gap-1.5 font-bold text-primary"><Timer className="w-4 h-4" /> {formatTime(elapsedTime)}</span>
                        </div>
                    </div>
                </div>

                <div className="flex gap-3">
                    {['FAILED', 'TIMED_OUT', 'INTERRUPTED', 'PENDING'].includes(scan.status) && (
                        <button
                            onClick={() => handleAction('RESUME')}
                            disabled={isActionLoading}
                            className="flex items-center justify-center gap-2 bg-green-600 text-white px-6 py-3 rounded-2xl font-bold hover:scale-105 transition-all shadow-lg shadow-green-600/20 active:scale-95 disabled:opacity-50"
                        >
                            <Play className="w-5 h-5" />
                            Resume Scan
                        </button>
                    )}
                    <button
                        onClick={() => handleAction('START')}
                        disabled={isActionLoading || scan.status === 'RUNNING'}
                        className="flex items-center justify-center gap-2 bg-primary text-white px-6 py-3 rounded-2xl font-bold hover:scale-105 transition-all shadow-lg shadow-primary/20 active:scale-95 disabled:bg-muted disabled:text-muted-foreground"
                    >
                        {isActionLoading ? <RefreshCw className="w-5 h-5 animate-spin" /> : <RefreshCw className="w-5 h-5" />}
                        New Rescan
                    </button>
                </div>
            </div>

            {/* Progress Bar for Running Scan */}
            {(scan.status === 'RUNNING' || (scan.status !== 'COMPLETED' && scan.currentIndex > 0)) && (
                <div className="bg-card border border-border rounded-3xl p-6 glass shadow-2xl overflow-hidden relative">
                    <div className="flex justify-between items-end mb-4">
                        <div className="space-y-1">
                            <div className="flex items-center gap-3">
                                <Activity className={`w-5 h-5 ${scan.status === 'RUNNING' ? 'text-blue-500 animate-pulse' : 'text-zinc-500'}`} />
                                <span className="text-sm font-bold uppercase tracking-widest">{scan.status === 'RUNNING' ? 'Scanning Network...' : 'Scan Interrupted'}</span>
                            </div>
                            {scan.status === 'RUNNING' && (
                                <p className="text-[10px] font-bold text-muted-foreground uppercase flex items-center gap-1.5">
                                    <Clock className="w-3 h-3" />
                                    Estimated Completion: <span className="text-primary">{eta ? eta : 'Calculating...'}</span>
                                </p>
                            )}
                        </div>
                        <span className="text-sm font-mono font-bold">{scan.currentIndex} / {scan.totalIps} IPs Completed</span>
                    </div>
                    <div className="h-3 w-full bg-accent/30 rounded-full overflow-hidden border border-border/50">
                        <div
                            className={`h-full transition-all duration-1000 ease-out ${scan.status === 'RUNNING' ? 'bg-primary shadow-[0_0_20px_rgba(var(--primary),0.5)]' : 'bg-zinc-500'}`}
                            style={{ width: `${progress}%` }}
                        />
                    </div>
                    {scan.status === 'TIMED_OUT' && (
                        <div className="mt-4 flex items-center gap-2 text-orange-500 text-xs font-bold bg-orange-500/10 p-3 rounded-xl border border-orange-500/20">
                            <AlertCircle className="w-4 h-4" /> Scan exceeded 30 minute safety timeout. Showing partial results.
                        </div>
                    )}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Stats Summary */}
                <div className="bg-card border border-border rounded-3xl p-6 glass">
                    <p className="text-sm font-semibold text-muted-foreground mb-4 uppercase tracking-widest">Findings Overview</p>
                    <div className="space-y-4">
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                            const count = scan.findings.filter(f => f.severity === sev).length;
                            return (
                                <div key={sev} className="flex items-center justify-between">
                                    <span className={`text-xs font-bold ${severityColors[sev].split(' ')[0]}`}>{sev}</span>
                                    <span className="text-xl font-bold">{count}</span>
                                </div>
                            );
                        })}
                        <div className="pt-4 border-t border-border flex items-center justify-between">
                            <span className="text-xs font-bold text-muted-foreground">TOTAL</span>
                            <span className="text-xl font-bold">{scan.findings.length}</span>
                        </div>
                    </div>

                    {scan.status === 'COMPLETED' && (
                        <div className="mt-8 p-4 bg-green-500/5 border border-green-500/10 rounded-2xl flex items-center gap-3">
                            <CheckCircle2 className="w-6 h-6 text-green-500" />
                            <div className="text-[10px] font-bold text-green-500 uppercase tracking-widest">Target Fully Verified</div>
                        </div>
                    )}
                </div>

                {/* Findings List */}
                <div className="lg:col-span-3 space-y-6">
                    <div className="relative">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground w-5 h-5" />
                        <input
                            type="text"
                            placeholder="Filter findings by IP, service, or system..."
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            className="w-full bg-card border border-border rounded-2xl py-4 pl-12 pr-4 focus:ring-2 focus:ring-primary outline-none transition-all"
                        />
                    </div>

                    <div className="space-y-4">
                        {filteredFindings.map((finding) => (
                            <div key={finding.id} className="bg-card border border-border rounded-2xl p-0 hover:border-primary/30 transition-all group overflow-hidden">
                                <div className="p-6">
                                    <div className="flex items-start justify-between gap-4 mb-6">
                                        <div className="flex gap-4">
                                            <div className={`p-2 rounded-lg border h-fit ${severityColors[finding.severity]}`}>
                                                {finding.severity === 'INFO' || finding.severity === 'LOW' ? (
                                                    <ShieldCheck className="w-5 h-5" />
                                                ) : (
                                                    <ShieldAlert className="w-5 h-5" />
                                                )}
                                            </div>
                                            <div>
                                                <h4 className="font-bold text-lg group-hover:text-primary transition-colors">
                                                    {finding.service} on {finding.ip}:{finding.port}
                                                </h4>
                                                <p className="text-sm text-muted-foreground mt-1">
                                                    {finding.description}
                                                    {finding.domains && (
                                                        <span className="block mt-2 text-[10px] uppercase tracking-tighter text-primary font-bold">
                                                            Linked Hostnames: {finding.domains.split(',').join(', ')}
                                                        </span>
                                                    )}
                                                </p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => toggleForensics(finding.id)}
                                                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-accent/50 hover:bg-accent text-[10px] font-bold uppercase tracking-wider transition-all border border-border"
                                            >
                                                <Search className="w-3 h-3" />
                                                Deep Inspect
                                            </button>
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-tighter border h-fit ${severityColors[finding.severity]}`}>
                                                {finding.severity}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Tech Details Grid */}
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 bg-accent/10 rounded-xl p-6 mb-6 border border-border/50">
                                        <div>
                                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Type</p>
                                            <p className="font-mono text-sm font-semibold">{finding.service || 'Unknown'}</p>
                                        </div>
                                        <div>
                                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Version</p>
                                            <p className="font-mono text-sm font-semibold text-primary">{finding.version || 'Detection Failed'}</p>
                                        </div>
                                        <div>
                                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Upstream</p>
                                            <p className="font-mono text-sm font-semibold">{finding.upstreamVersion || 'Unknown'}</p>
                                        </div>
                                        <div>
                                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Confidence</p>
                                            <div className="flex items-center gap-1.5">
                                                <div className="h-1.5 w-12 bg-accent rounded-full overflow-hidden">
                                                    <div className="h-full bg-green-500 w-[100%]"></div>
                                                </div>
                                                <p className="font-mono text-[10px] font-bold">100%</p>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Tech Stack - ENTERPRISE VIEW */}
                                    {finding.techStack && (
                                        <div className="flex flex-wrap gap-2 mb-6 p-4 bg-indigo-500/5 rounded-xl border border-indigo-500/10">
                                            {finding.techStack.split(',').map(tech => (
                                                <div key={tech} className="flex items-center gap-2 px-3 py-1 bg-background/50 border border-indigo-500/20 rounded-full">
                                                    <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.8)]" />
                                                    <span className="text-[10px] font-black uppercase tracking-widest text-indigo-300">
                                                        {tech.trim()}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {/* Issues & Remediation Section - PREMIUM STYLE */}
                                    {finding.vulnerability && (
                                        <div className="space-y-6">
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                                <div className="space-y-3">
                                                    <p className="text-[10px] font-bold text-red-500 uppercase tracking-widest flex items-center gap-2">
                                                        <AlertTriangle className="w-3 h-3" /> Identified Issue
                                                    </p>
                                                    <div className="p-4 bg-red-500/5 border border-red-500/10 rounded-xl">
                                                        <p className="text-sm font-bold text-red-500">{finding.vulnerability.split(';')[0]}</p>
                                                        <p className="text-[11px] text-red-500/70 mt-1 leading-relaxed">
                                                            This configuration lacks critical security baselines and may be vulnerable to active exploitation.
                                                        </p>
                                                    </div>
                                                </div>
                                                <div className="space-y-3">
                                                    <p className="text-[10px] font-bold text-green-500 uppercase tracking-widest flex items-center gap-2">
                                                        <ShieldCheck className="w-3 h-3" /> Remediation Tip
                                                    </p>
                                                    <div className="p-4 bg-green-500/5 border border-green-500/10 rounded-xl">
                                                        <p className="text-sm font-semibold leading-relaxed">
                                                            {finding.remediation || "Restrict access to this port via firewall and ensure the software is updated to the latest stable release."}
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Forensic Inspection Section (Expandable) */}
                                    {expandedForensics.has(finding.id) && (
                                        <div className="mt-8 pt-8 border-t border-border animate-in slide-in-from-top-4 duration-300">
                                            <div className="space-y-6">
                                                <div>
                                                    <h5 className="text-[10px] font-bold text-primary uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                                                        <Terminal className="w-3.5 h-3.5" /> High-Level Forensic Trace
                                                    </h5>
                                                    <div className="bg-zinc-950 rounded-xl p-4 font-mono text-[11px] leading-relaxed border border-white/5 shadow-2xl">
                                                        {finding.forensics?.split('\n').map((line, i) => (
                                                            <div key={i} className="flex gap-3 mb-1.5 last:mb-0">
                                                                <span className="text-zinc-600 shrink-0">[{i + 1}]</span>
                                                                <span className={line.includes('Logic') ? 'text-blue-400' : 'text-zinc-300'}>
                                                                    {line}
                                                                </span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                                    <div>
                                                        <h5 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-3 flex items-center gap-2">
                                                            <Eye className="w-3 h-3" /> Raw Data Evidence (String)
                                                        </h5>
                                                        <div className="bg-accent/20 rounded-xl p-4 border border-border/50 break-all font-mono text-[10px] min-h-[80px]">
                                                            {finding.banner || 'No data was returned during active probe.'}
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <h5 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-3 flex items-center gap-2">
                                                            <Code className="w-3 h-3" /> Binary Repr (Hex)
                                                        </h5>
                                                        <div className="bg-accent/20 rounded-xl p-4 border border-border/50 break-all font-mono text-[10px] min-h-[80px] text-zinc-500">
                                                            {finding.banner ? toHex(finding.banner) : 'N/A'}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))}
                        {filteredFindings.length === 0 && (
                            <div className="py-20 text-center border-2 border-dashed border-border rounded-3xl text-muted-foreground">
                                No matching findings discovered.
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
