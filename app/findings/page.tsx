"use client";

import { useEffect, useState } from 'react';
import {
    ShieldAlert, Globe, Server, AlertTriangle, ShieldCheck,
    Search, Terminal, Eye, Code, Activity, Filter, ChevronDown,
    RefreshCw, Download, Shield, ExternalLink, Zap, Clock
} from 'lucide-react';
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
    vulnerability?: string | null;
    remediation?: string | null;
    forensics?: string | null;
    upstreamVersion?: string | null;
    domains?: string | null;
    techStack?: string | null;
    updatedAt?: string;
    scans?: {
        target: string;
    }[];
}

export default function FindingsPage() {
    const [findings, setFindings] = useState<Finding[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<string>('ALL');
    const [searchQuery, setSearchQuery] = useState('');
    const [expandedForensics, setExpandedForensics] = useState<Set<string>>(new Set());

    const toggleForensics = (fid: string) => {
        const next = new Set(expandedForensics);
        if (next.has(fid)) next.delete(fid);
        else next.add(fid);
        setExpandedForensics(next);
    };

    const toHex = (str: string) => {
        return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    };

    const fetchFindings = async () => {
        setLoading(true);
        try {
            const res = await axios.get('/api/findings');
            setFindings(res.data);
        } catch (error) {
            console.error('Failed to fetch findings', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchFindings();
    }, []);

    // Filter findings (excluding DNS Discovery meta-finding)
    const realFindings = findings.filter(f => f.ip !== '0.0.0.0');

    const filteredFindings = realFindings
        .filter(f => filter === 'ALL' || f.severity === filter)
        .filter(f => {
            if (!searchQuery) return true;
            const q = searchQuery.toLowerCase();
            return f.ip.includes(q) ||
                f.service?.toLowerCase().includes(q) ||
                f.domains?.toLowerCase().includes(q) ||
                f.vulnerability?.toLowerCase().includes(q);
        });

    const severityColors: Record<string, string> = {
        CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/20',
        HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
        MEDIUM: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
        LOW: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
        INFO: 'text-zinc-400 bg-zinc-400/10 border-zinc-400/20',
    };

    const severityBg: Record<string, string> = {
        CRITICAL: 'bg-red-500',
        HIGH: 'bg-orange-500',
        MEDIUM: 'bg-yellow-500',
        LOW: 'bg-blue-500',
        INFO: 'bg-zinc-500',
    };

    // Stats
    const criticalCount = realFindings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = realFindings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = realFindings.filter(f => f.severity === 'MEDIUM').length;
    const totalVulns = realFindings.filter(f => f.vulnerability).length;

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-black tracking-tight">Security Findings</h1>
                    <p className="text-muted-foreground mt-1">Detailed vulnerability and exposure report</p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchFindings}
                        className="p-2 rounded-xl border border-border hover:bg-accent transition-all"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                    <button className="p-2 rounded-xl border border-border hover:bg-accent transition-all" title="Export">
                        <Download className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10"><Shield className="w-5 h-5 text-primary" /></div>
                        <div>
                            <p className="text-2xl font-black">{realFindings.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Total</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-red-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-red-500/10"><AlertTriangle className="w-5 h-5 text-red-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-red-500">{criticalCount}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Critical</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-orange-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-orange-500/10"><ShieldAlert className="w-5 h-5 text-orange-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-orange-500">{highCount}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">High</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-yellow-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-yellow-500/10"><Zap className="w-5 h-5 text-yellow-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-yellow-500">{mediumCount}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Medium</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10"><Eye className="w-5 h-5 text-purple-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{totalVulns}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">With Issues</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Filters & Search */}
            <div className="flex flex-col md:flex-row gap-4">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground w-4 h-4" />
                    <input
                        type="text"
                        placeholder="Search by IP, service, domain, or vulnerability..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-card border border-border rounded-xl py-2.5 pl-10 pr-4 text-sm focus:ring-2 focus:ring-primary outline-none"
                    />
                </div>
                <div className="flex items-center gap-1 bg-card border border-border p-1 rounded-xl">
                    {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
                        <button
                            key={s}
                            onClick={() => setFilter(s)}
                            className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all ${filter === s
                                    ? 'bg-primary text-primary-foreground shadow'
                                    : 'text-muted-foreground hover:bg-accent'
                                }`}
                        >
                            {s}
                        </button>
                    ))}
                </div>
            </div>

            {/* Findings List */}
            <div className="space-y-4">
                {loading ? (
                    <div className="bg-card border border-border rounded-2xl p-12 text-center">
                        <Activity className="w-10 h-10 animate-spin mx-auto text-primary opacity-50" />
                        <p className="mt-4 text-sm text-muted-foreground">Loading findings...</p>
                    </div>
                ) : filteredFindings.length === 0 ? (
                    <div className="bg-card border border-dashed border-border rounded-2xl p-12 text-center">
                        <ShieldCheck className="w-12 h-12 mx-auto text-muted-foreground/30 mb-4" />
                        <h3 className="font-bold text-lg mb-1">No Findings Match</h3>
                        <p className="text-sm text-muted-foreground">
                            {realFindings.length === 0 ? 'Run a scan to discover findings.' : 'Adjust your filter criteria.'}
                        </p>
                    </div>
                ) : (
                    filteredFindings.map((finding) => (
                        <div
                            key={finding.id}
                            className="bg-card border border-border rounded-2xl overflow-hidden hover:border-primary/30 transition-all group"
                        >
                            {/* Finding Header */}
                            <div className="p-4 flex items-start gap-4">
                                {/* Severity Bar */}
                                <div className={`w-1.5 h-16 rounded-full ${severityBg[finding.severity]} shrink-0`} />

                                {/* Main Content */}
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-start justify-between gap-4">
                                        <div>
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <h4 className="font-bold text-lg group-hover:text-primary transition-colors">
                                                    {finding.service || 'Unknown'}
                                                    <span className="text-muted-foreground font-normal">:{finding.port}</span>
                                                </h4>
                                                <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase border ${severityColors[finding.severity]}`}>
                                                    {finding.severity}
                                                </span>
                                                {finding.version && (
                                                    <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-accent text-muted-foreground">
                                                        v{finding.version}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                                                <span className="font-mono">{finding.ip}</span>
                                                {finding.domains && (
                                                    <>
                                                        <span>•</span>
                                                        <span className="text-primary">{finding.domains.split(',')[0]}</span>
                                                    </>
                                                )}
                                                {finding.updatedAt && (
                                                    <>
                                                        <span>•</span>
                                                        <span className="flex items-center gap-1">
                                                            <Clock className="w-3 h-3" />
                                                            {new Date(finding.updatedAt).toLocaleDateString()}
                                                        </span>
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => toggleForensics(finding.id)}
                                            className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${expandedForensics.has(finding.id)
                                                    ? 'bg-primary text-primary-foreground'
                                                    : 'bg-accent hover:bg-accent/80'
                                                }`}
                                        >
                                            <Terminal className="w-3.5 h-3.5" />
                                            {expandedForensics.has(finding.id) ? 'Hide' : 'Inspect'}
                                        </button>
                                    </div>

                                    {/* Description */}
                                    <p className="text-sm text-muted-foreground mt-2">
                                        {finding.description || 'Service detected during port scan.'}
                                    </p>

                                    {/* Vulnerability Alert */}
                                    {finding.vulnerability && (
                                        <div className="mt-3 flex items-start gap-3 p-3 rounded-xl bg-red-500/5 border border-red-500/10">
                                            <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                                            <div className="flex-1">
                                                <p className="text-sm font-bold text-red-400">{finding.vulnerability.split(';')[0]}</p>
                                                {finding.remediation && (
                                                    <p className="text-xs text-muted-foreground mt-1">{finding.remediation}</p>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* Tech Stack */}
                                    {finding.techStack && (
                                        <div className="mt-3 flex flex-wrap gap-1.5">
                                            {finding.techStack.split(',').filter(t => t.trim()).slice(0, 5).map((tech, i) => (
                                                <span key={i} className="px-2 py-0.5 rounded text-[10px] font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                    {tech.trim()}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Expanded Forensics */}
                            {expandedForensics.has(finding.id) && (
                                <div className="border-t border-border bg-muted/30 p-4 animate-in slide-in-from-top-2 duration-200">
                                    <div className="space-y-4">
                                        {/* Forensics Log */}
                                        <div>
                                            <h5 className="text-[10px] font-bold text-primary uppercase tracking-widest mb-2 flex items-center gap-2">
                                                <Terminal className="w-3 h-3" /> Discovery Log
                                            </h5>
                                            <div className="bg-zinc-950 rounded-xl p-4 border border-white/5 font-mono text-[11px] max-h-48 overflow-y-auto">
                                                {finding.forensics?.split('\n').map((line, i) => (
                                                    <div key={i} className={`${line.includes('Logic') || line.includes('->') ? 'text-blue-400' : line.includes('Warning') || line.includes('⚠') ? 'text-yellow-400' : 'text-zinc-300'}`}>
                                                        {line}
                                                    </div>
                                                )) || <span className="text-zinc-500">No forensic data available</span>}
                                            </div>
                                        </div>

                                        {/* Raw Banner */}
                                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                            <div>
                                                <h5 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Eye className="w-3 h-3" /> Raw Banner
                                                </h5>
                                                <div className="bg-accent/30 rounded-xl p-3 border border-border font-mono text-[10px] break-all max-h-24 overflow-y-auto">
                                                    {finding.banner || 'No banner captured'}
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-2">
                                                    <Code className="w-3 h-3" /> Hex Representation
                                                </h5>
                                                <div className="bg-accent/30 rounded-xl p-3 border border-border font-mono text-[10px] text-zinc-500 break-all max-h-24 overflow-y-auto">
                                                    {finding.banner ? toHex(finding.banner) : 'N/A'}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>

            {/* Results Count */}
            {!loading && filteredFindings.length > 0 && (
                <p className="text-xs text-muted-foreground text-center">
                    Showing {filteredFindings.length} of {realFindings.length} findings
                </p>
            )}
        </div>
    );
}
