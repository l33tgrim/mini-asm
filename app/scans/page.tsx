"use client";

import { useEffect, useState } from 'react';
import {
    ScanSearch, Play, Plus, Search, Info, RefreshCw, ChevronRight,
    Globe, Target, Activity, Shield, Clock, CheckCircle2, XCircle,
    Loader2, Zap, Server, BarChart3
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import axios from 'axios';

interface Scan {
    id: string;
    target: string;
    status: string;
    type: string;
    createdAt: string;
    completedAt?: string;
    totalIps?: number;
    currentIndex?: number;
    _count?: {
        findings: number;
    };
}

export default function ScansPage() {
    const router = useRouter();
    const [scans, setScans] = useState<Scan[]>([]);
    const [target, setTarget] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [loading, setLoading] = useState(true);
    const [scanType, setScanType] = useState<'quick' | 'deep' | 'full'>('quick');

    const fetchScans = async () => {
        try {
            const res = await axios.get('/api/scans');
            setScans(res.data);
        } catch (error) {
            console.error('Failed to fetch scans', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
        const interval = setInterval(fetchScans, 5000); // Auto-refresh for running scans
        return () => clearInterval(interval);
    }, []);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) return;

        setIsScanning(true);
        try {
            const res = await axios.post('/api/scans', { target });
            router.push(`/scans/${res.data.id}`);
        } catch (error) {
            alert('Scanning failed. Check target format (domain, IP, or /24 CIDR)');
        } finally {
            setIsScanning(false);
        }
    };

    const runningScans = scans.filter(s => s.status === 'RUNNING');
    const completedScans = scans.filter(s => s.status === 'COMPLETED');
    const totalFindings = scans.reduce((acc, s) => acc + (s._count?.findings || 0), 0);

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'RUNNING': return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />;
            case 'COMPLETED': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
            case 'FAILED': return <XCircle className="w-4 h-4 text-red-500" />;
            default: return <Clock className="w-4 h-4 text-yellow-500" />;
        }
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'RUNNING': return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
            case 'COMPLETED': return 'bg-green-500/10 text-green-500 border-green-500/20';
            case 'FAILED': return 'bg-red-500/10 text-red-500 border-red-500/20';
            default: return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
        }
    };

    return (
        <div className="space-y-6 animate-in fade-in duration-700">
            {/* Header */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-black tracking-tight">Scan Operations Center</h1>
                    <p className="text-muted-foreground mt-1">Initiate and manage attack surface discovery scans</p>
                </div>
                <button
                    onClick={fetchScans}
                    className="self-start p-2 rounded-xl border border-border hover:bg-accent transition-all"
                >
                    <RefreshCw className="w-4 h-4" />
                </button>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10"><BarChart3 className="w-5 h-5 text-primary" /></div>
                        <div>
                            <p className="text-2xl font-black">{scans.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Total Scans</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-blue-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/10"><Activity className="w-5 h-5 text-blue-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-blue-500">{runningScans.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Running</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-green-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-green-500/10"><CheckCircle2 className="w-5 h-5 text-green-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-green-500">{completedScans.length}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Completed</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10"><Shield className="w-5 h-5 text-purple-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{totalFindings}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Total Findings</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* New Scan Card */}
            <div className="bg-gradient-to-br from-card to-primary/5 border border-primary/20 rounded-2xl p-6 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-primary/10 to-transparent rounded-full blur-3xl pointer-events-none" />

                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="p-2 rounded-xl bg-primary/20">
                            <Target className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                            <h3 className="text-lg font-bold">New Discovery Scan</h3>
                            <p className="text-xs text-muted-foreground">Enter a domain, IP address, or CIDR range to scan</p>
                        </div>
                    </div>

                    {/* Scan Type Selector */}
                    <div className="flex gap-2 mb-4">
                        {[
                            { id: 'quick', label: 'Quick Scan', desc: 'Common ports only', icon: Zap },
                            { id: 'deep', label: 'Deep Scan', desc: 'Extended port range', icon: ScanSearch },
                            { id: 'full', label: 'Full Discovery', desc: 'Complete enumeration', icon: Globe },
                        ].map((type) => (
                            <button
                                key={type.id}
                                onClick={() => setScanType(type.id as any)}
                                className={`flex-1 p-3 rounded-xl border transition-all ${scanType === type.id
                                        ? 'border-primary bg-primary/10 text-primary'
                                        : 'border-border hover:border-primary/30 hover:bg-accent/30'
                                    }`}
                            >
                                <type.icon className="w-4 h-4 mx-auto mb-1" />
                                <p className="text-xs font-bold">{type.label}</p>
                                <p className="text-[9px] text-muted-foreground">{type.desc}</p>
                            </button>
                        ))}
                    </div>

                    <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-3">
                        <div className="flex-1 relative">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground w-5 h-5" />
                            <input
                                type="text"
                                placeholder="e.g. example.com, 192.168.1.1, or 10.0.0.0/24"
                                disabled={isScanning}
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                className="w-full bg-background/50 border border-border rounded-xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-primary outline-none transition-all placeholder:text-muted-foreground/50 font-mono text-sm"
                            />
                        </div>
                        <button
                            type="submit"
                            disabled={isScanning || !target}
                            className={`px-6 py-3 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${isScanning
                                    ? 'bg-muted text-muted-foreground cursor-not-allowed'
                                    : 'bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20'
                                }`}
                        >
                            {isScanning ? (
                                <>
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Starting...
                                </>
                            ) : (
                                <>
                                    <Play className="w-4 h-4 fill-current" />
                                    Start Scan
                                </>
                            )}
                        </button>
                    </form>

                    <div className="mt-3 flex items-center gap-2 text-[10px] text-muted-foreground">
                        <Info className="w-3 h-3" />
                        Supports domains (with subdomain enumeration), single IPs, and CIDR /24 ranges
                    </div>
                </div>
            </div>

            {/* Running Scans */}
            {runningScans.length > 0 && (
                <div className="space-y-3">
                    <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-2">
                        <Activity className="w-4 h-4 text-blue-500 animate-pulse" />
                        Active Scans
                    </h3>
                    {runningScans.map((scan) => (
                        <div
                            key={scan.id}
                            onClick={() => router.push(`/scans/${scan.id}`)}
                            className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 cursor-pointer hover:border-blue-500/40 transition-all"
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-blue-500/10">
                                        <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
                                    </div>
                                    <div>
                                        <p className="font-mono font-bold">{scan.target}</p>
                                        <p className="text-xs text-muted-foreground">
                                            {scan.currentIndex || 0} / {scan.totalIps || '?'} IPs scanned
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4">
                                    <div className="w-32 h-2 bg-muted rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-blue-500 transition-all duration-500"
                                            style={{ width: `${scan.totalIps ? ((scan.currentIndex || 0) / scan.totalIps * 100) : 0}%` }}
                                        />
                                    </div>
                                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Scan History */}
            <div className="bg-card border border-border rounded-2xl overflow-hidden">
                <div className="p-4 border-b border-border flex items-center justify-between">
                    <h3 className="font-bold flex items-center gap-2">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        Scan History
                    </h3>
                    <span className="text-xs text-muted-foreground">{scans.length} total scans</span>
                </div>

                <div className="divide-y divide-border">
                    {scans.length === 0 && !loading ? (
                        <div className="p-12 text-center">
                            <ScanSearch className="w-12 h-12 mx-auto text-muted-foreground/30 mb-3" />
                            <p className="text-muted-foreground">No scans found. Start your first scan above.</p>
                        </div>
                    ) : (
                        scans.map((scan) => (
                            <div
                                key={scan.id}
                                onClick={() => router.push(`/scans/${scan.id}`)}
                                className="p-4 hover:bg-accent/30 transition-colors cursor-pointer group flex items-center justify-between"
                            >
                                <div className="flex items-center gap-4">
                                    <div className={`p-2 rounded-lg ${scan.status === 'COMPLETED' ? 'bg-green-500/10' :
                                            scan.status === 'RUNNING' ? 'bg-blue-500/10' : 'bg-red-500/10'
                                        }`}>
                                        {getStatusIcon(scan.status)}
                                    </div>
                                    <div>
                                        <p className="font-mono font-bold text-sm group-hover:text-primary transition-colors">{scan.target}</p>
                                        <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                                            <span>{scan.totalIps || 0} IPs</span>
                                            <span>•</span>
                                            <span>{scan._count?.findings || 0} findings</span>
                                            <span>•</span>
                                            <span className="uppercase text-[10px]">{scan.type}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase border ${getStatusColor(scan.status)}`}>
                                        {scan.status}
                                    </span>
                                    <div className="text-right">
                                        <p className="text-xs text-muted-foreground">
                                            {new Date(scan.createdAt).toLocaleDateString()}
                                        </p>
                                        <p className="text-[10px] text-muted-foreground">
                                            {new Date(scan.createdAt).toLocaleTimeString()}
                                        </p>
                                    </div>
                                    <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}
