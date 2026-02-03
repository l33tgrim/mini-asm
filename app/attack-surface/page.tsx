"use client";

import { useEffect, useState } from 'react';
import {
    Globe, Server, Shield, AlertTriangle, ShieldCheck, ChevronDown, ChevronUp,
    Search, Terminal, ExternalLink, Activity, Info, Wifi, Lock, Database, Mail, Cloud
} from 'lucide-react';
import axios from 'axios';
import { useRouter } from 'next/navigation';

interface Finding {
    id: string;
    ip: string;
    port: number;
    service: string | null;
    version: string | null;
    severity: string;
    description: string | null;
    vulnerability: string | null;
    domains: string | null;
    techStack: string | null;
    forensics: string | null;
    updatedAt: string;
}

interface AttackSurfaceHost {
    ip: string;
    isAlive: boolean;
    lastSeen: string;
    ports: {
        port: number;
        service: string | null;
        version: string | null;
        severity: string;
        description: string | null;
        forensics: string | null;
        vulnerabilities: string[];
    }[];
    maxSeverity: string;
    domains: string[];
    techStack: string[];
}

export default function AttackSurfacePage() {
    const [hosts, setHosts] = useState<AttackSurfaceHost[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');
    const [scanningIp, setScanningIp] = useState<string | null>(null);
    const [expandedHost, setExpandedHost] = useState<string | null>(null);
    const router = useRouter();

    // DNS Discovery state for consolidated reconnaissance findings
    const [dnsDiscovery, setDnsDiscovery] = useState<{
        forensics: string;
        vulnerabilities: string[];
        severity: string;
        description: string;
    } | null>(null);

    const handleQuickScan = async (target: string) => {
        try {
            setScanningIp(target);
            const res = await axios.post('/api/scans', { target });
            router.push(`/scans/${res.data.id}`);
        } catch (error) {
            console.error('Failed to start quick scan', error);
            alert('Failed to start scan. Please try again.');
        } finally {
            setScanningIp(null);
        }
    };

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await axios.get('/api/findings');
                const findings: Finding[] = res.data;

                // Extract DNS Discovery finding (special IP 0.0.0.0)
                const dnsDiscoveryFinding = findings.find(f => f.ip === '0.0.0.0' && f.service === 'DNS Discovery');
                if (dnsDiscoveryFinding) {
                    setDnsDiscovery({
                        forensics: dnsDiscoveryFinding.forensics || '',
                        vulnerabilities: dnsDiscoveryFinding.vulnerability ? dnsDiscoveryFinding.vulnerability.split(';').filter(v => v.trim()) : [],
                        severity: dnsDiscoveryFinding.severity,
                        description: dnsDiscoveryFinding.description || ''
                    });
                }

                const hostMap = new Map<string, AttackSurfaceHost>();

                // Filter out DNS Discovery meta-finding
                findings.filter(f => f.ip !== '0.0.0.0').forEach(f => {
                    if (!hostMap.has(f.ip)) {
                        hostMap.set(f.ip, {
                            ip: f.ip,
                            isAlive: true,
                            lastSeen: f.updatedAt,
                            ports: [],
                            maxSeverity: 'INFO',
                            domains: [],
                            techStack: []
                        });
                    }

                    const host = hostMap.get(f.ip)!;

                    if (f.domains) {
                        f.domains.split(',').forEach(d => {
                            if (!host.domains.includes(d.trim())) host.domains.push(d.trim());
                        });
                    }

                    if (f.techStack) {
                        f.techStack.split(',').forEach(t => {
                            const cleanT = t.trim();
                            if (cleanT && !host.techStack.includes(cleanT)) host.techStack.push(cleanT);
                        });
                    }

                    host.ports.push({
                        port: f.port,
                        service: f.service,
                        version: f.version,
                        severity: f.severity,
                        description: f.description,
                        forensics: f.forensics,
                        vulnerabilities: f.vulnerability ? f.vulnerability.split(';').filter(v => v.trim()) : []
                    });

                    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
                    const currentMax = severityOrder[host.maxSeverity as keyof typeof severityOrder] || 0;
                    const thisSev = severityOrder[f.severity as keyof typeof severityOrder] || 0;
                    if (thisSev > currentMax) host.maxSeverity = f.severity;
                });

                setHosts(Array.from(hostMap.values()).sort((a, b) => {
                    const sevOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
                    return (sevOrder[b.maxSeverity as keyof typeof sevOrder] || 0) - (sevOrder[a.maxSeverity as keyof typeof sevOrder] || 0);
                }));
            } catch (error) {
                console.error('Failed to fetch attack surface', error);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    const severityColors: Record<string, string> = {
        CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/30',
        HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
        MEDIUM: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
        LOW: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
        INFO: 'text-zinc-400 bg-zinc-400/10 border-zinc-400/30',
    };

    const severityBg: Record<string, string> = {
        CRITICAL: 'bg-red-500',
        HIGH: 'bg-orange-500',
        MEDIUM: 'bg-yellow-500',
        LOW: 'bg-blue-500',
        INFO: 'bg-zinc-500',
    };

    const filteredHosts = hosts.filter(h =>
        h.ip.includes(filter) ||
        h.domains.some(d => d.toLowerCase().includes(filter.toLowerCase())) ||
        h.ports.some(p => p.service?.toLowerCase().includes(filter.toLowerCase()))
    );

    // Statistics
    const totalAssets = hosts.length;
    const criticalAssets = hosts.filter(h => h.maxSeverity === 'CRITICAL').length;
    const highAssets = hosts.filter(h => h.maxSeverity === 'HIGH').length;
    const totalPorts = hosts.reduce((acc, h) => acc + h.ports.filter(p => p.port > 0).length, 0);
    const totalVulns = hosts.reduce((acc, h) => acc + h.ports.reduce((a, p) => a + p.vulnerabilities.length, 0), 0);

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-black tracking-tight">Attack Surface Inventory</h1>
                    <p className="text-muted-foreground mt-1">Complete visibility into your external attack surface</p>
                </div>
                <div className="relative w-full lg:w-80">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground w-4 h-4" />
                    <input
                        type="text"
                        placeholder="Search assets, domains, services..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="w-full bg-card border border-border rounded-xl py-2.5 pl-10 pr-4 text-sm focus:ring-2 focus:ring-primary outline-none"
                    />
                </div>
            </div>

            {/* Stats Cards - Qualys/RiskIQ Style */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10"><Globe className="w-5 h-5 text-primary" /></div>
                        <div>
                            <p className="text-2xl font-black">{totalAssets}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Total Assets</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-red-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-red-500/10"><AlertTriangle className="w-5 h-5 text-red-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-red-500">{criticalAssets}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Critical</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-orange-500/20 rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-orange-500/10"><Shield className="w-5 h-5 text-orange-500" /></div>
                        <div>
                            <p className="text-2xl font-black text-orange-500">{highAssets}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">High Risk</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/10"><Wifi className="w-5 h-5 text-blue-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{totalPorts}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Open Ports</p>
                        </div>
                    </div>
                </div>
                <div className="bg-card border border-border rounded-2xl p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10"><Lock className="w-5 h-5 text-purple-500" /></div>
                        <div>
                            <p className="text-2xl font-black">{totalVulns}</p>
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">Exposures</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* DNS & Email Security Panel */}
            {dnsDiscovery && (
                <div className="bg-gradient-to-r from-indigo-500/5 to-purple-500/5 border border-indigo-500/20 rounded-2xl p-5">
                    <div className="flex items-start gap-4">
                        <div className="p-3 rounded-xl bg-indigo-500/10 shrink-0">
                            <Mail className="w-6 h-6 text-indigo-400" />
                        </div>
                        <div className="flex-1 space-y-3">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-lg font-bold">Domain Reconnaissance</h3>
                                    <p className="text-sm text-muted-foreground">{dnsDiscovery.description}</p>
                                </div>
                                {dnsDiscovery.severity !== 'INFO' && (
                                    <span className={`px-3 py-1 rounded-lg text-[10px] font-black uppercase ${severityColors[dnsDiscovery.severity]}`}>
                                        {dnsDiscovery.vulnerabilities.length} Security Issue{dnsDiscovery.vulnerabilities.length !== 1 ? 's' : ''}
                                    </span>
                                )}
                            </div>

                            {/* Security Issues */}
                            {dnsDiscovery.vulnerabilities.length > 0 && (
                                <div className="flex flex-wrap gap-2">
                                    {dnsDiscovery.vulnerabilities.map((v, i) => (
                                        <span key={i} className="px-2 py-1 rounded-lg text-xs font-medium bg-yellow-500/10 text-yellow-500 border border-yellow-500/20 flex items-center gap-1">
                                            <AlertTriangle className="w-3 h-3" />
                                            {v}
                                        </span>
                                    ))}
                                </div>
                            )}

                            {/* Forensics Details */}
                            {dnsDiscovery.forensics && (
                                <details className="group">
                                    <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                                        <ChevronDown className="w-3 h-3 group-open:rotate-180 transition-transform" />
                                        View Full Discovery Details
                                    </summary>
                                    <pre className="mt-3 p-4 bg-muted/50 rounded-xl text-[11px] font-mono text-muted-foreground whitespace-pre-wrap overflow-x-auto">
                                        {dnsDiscovery.forensics}
                                    </pre>
                                </details>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Asset List - Card Based */}
            <div className="space-y-3">
                {loading ? (
                    <div className="bg-card border border-border rounded-2xl p-12 text-center">
                        <Activity className="w-10 h-10 animate-spin mx-auto text-primary opacity-50" />
                        <p className="mt-4 text-sm text-muted-foreground">Loading attack surface data...</p>
                    </div>
                ) : filteredHosts.length === 0 ? (
                    <div className="bg-card border border-border rounded-2xl p-12 text-center">
                        <Globe className="w-10 h-10 mx-auto text-muted-foreground opacity-50" />
                        <p className="mt-4 text-sm text-muted-foreground">No assets found. Run a scan to discover your attack surface.</p>
                    </div>
                ) : (
                    filteredHosts.map(host => (
                        <div key={host.ip} className="bg-card border border-border rounded-2xl overflow-hidden transition-all hover:border-primary/30">
                            {/* Asset Header */}
                            <div
                                className="p-4 cursor-pointer flex items-center justify-between"
                                onClick={() => setExpandedHost(expandedHost === host.ip ? null : host.ip)}
                            >
                                <div className="flex items-center gap-4">
                                    {/* Severity Indicator */}
                                    <div className={`w-2 h-12 rounded-full ${severityBg[host.maxSeverity]}`} />

                                    {/* IP and Domains */}
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <p className="font-mono font-bold text-lg">{host.ip}</p>
                                            <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${severityColors[host.maxSeverity]}`}>
                                                {host.maxSeverity}
                                            </span>
                                            <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-green-500/10 text-green-500 border border-green-500/20">
                                                ALIVE
                                            </span>
                                        </div>
                                        {host.domains.length > 0 && (
                                            <div className="flex flex-wrap gap-1 mt-1">
                                                {host.domains.slice(0, 5).map(d => (
                                                    <span key={d} className="text-[10px] font-medium text-primary">{d}</span>
                                                ))}
                                                {host.domains.length > 5 && (
                                                    <span className="text-[10px] text-muted-foreground">+{host.domains.length - 5} more</span>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Right Side Stats */}
                                <div className="flex items-center gap-6">
                                    <div className="text-center">
                                        <p className="text-lg font-bold">{host.ports.filter(p => p.port > 0).length}</p>
                                        <p className="text-[9px] uppercase text-muted-foreground font-bold">Ports</p>
                                    </div>
                                    <div className="text-center">
                                        <p className="text-lg font-bold">{host.ports.reduce((a, p) => a + p.vulnerabilities.length, 0)}</p>
                                        <p className="text-[9px] uppercase text-muted-foreground font-bold">Issues</p>
                                    </div>
                                    <div className="text-center">
                                        <p className="text-lg font-bold">{host.techStack.length}</p>
                                        <p className="text-[9px] uppercase text-muted-foreground font-bold">Tech</p>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleQuickScan(host.ip); }}
                                            disabled={scanningIp === host.ip}
                                            className="p-2 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-all disabled:opacity-50"
                                            title="Rescan"
                                        >
                                            {scanningIp === host.ip ? (
                                                <Activity className="w-4 h-4 animate-spin" />
                                            ) : (
                                                <Terminal className="w-4 h-4" />
                                            )}
                                        </button>
                                        {expandedHost === host.ip ? (
                                            <ChevronUp className="w-5 h-5 text-muted-foreground" />
                                        ) : (
                                            <ChevronDown className="w-5 h-5 text-muted-foreground" />
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Expanded Details */}
                            {expandedHost === host.ip && (
                                <div className="border-t border-border bg-muted/30 p-4 space-y-4">
                                    {/* Tech Stack */}
                                    {host.techStack.length > 0 && (
                                        <div>
                                            <p className="text-[10px] uppercase font-bold text-muted-foreground mb-2">Technology Stack</p>
                                            <div className="flex flex-wrap gap-2">
                                                {host.techStack.map(t => (
                                                    <span key={t} className="px-2 py-1 rounded-lg text-xs font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                        {t}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Domains */}
                                    {host.domains.length > 0 && (
                                        <div>
                                            <p className="text-[10px] uppercase font-bold text-muted-foreground mb-2">Associated Domains</p>
                                            <div className="flex flex-wrap gap-2">
                                                {host.domains.map(d => (
                                                    <button
                                                        key={d}
                                                        onClick={() => handleQuickScan(d)}
                                                        className="px-2 py-1 rounded-lg text-xs font-medium bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 transition-all"
                                                    >
                                                        {d}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Services/Ports */}
                                    <div>
                                        <p className="text-[10px] uppercase font-bold text-muted-foreground mb-2">Open Services</p>
                                        <div className="grid gap-2">
                                            {host.ports.filter(p => p.port > 0).map(p => (
                                                <div key={p.port} className={`p-3 rounded-xl border ${severityColors[p.severity]} bg-opacity-50`}>
                                                    <div className="flex items-start justify-between">
                                                        <div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-mono font-bold">:{p.port}</span>
                                                                <span className="text-sm font-medium">{p.service || 'Unknown'}</span>
                                                                {p.version && (
                                                                    <span className="text-xs font-mono text-muted-foreground">{p.version}</span>
                                                                )}
                                                            </div>
                                                            {p.description && (
                                                                <p className="text-xs text-muted-foreground mt-1">{p.description}</p>
                                                            )}
                                                        </div>
                                                        <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${severityColors[p.severity]}`}>
                                                            {p.severity}
                                                        </span>
                                                    </div>

                                                    {/* Vulnerabilities */}
                                                    {p.vulnerabilities.length > 0 && (
                                                        <div className="mt-2 pt-2 border-t border-border/50">
                                                            <p className="text-[9px] uppercase font-bold text-muted-foreground mb-1">Exposures</p>
                                                            <ul className="space-y-1">
                                                                {p.vulnerabilities.map((v, i) => (
                                                                    <li key={i} className="text-xs flex items-start gap-2">
                                                                        <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-yellow-500" />
                                                                        <span>{v}</span>
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        </div>
                                                    )}

                                                    {/* Forensics */}
                                                    {p.forensics && (
                                                        <div className="mt-2 pt-2 border-t border-border/50">
                                                            <p className="text-[9px] uppercase font-bold text-muted-foreground mb-1">Discovery Details</p>
                                                            <pre className="text-[10px] font-mono text-muted-foreground whitespace-pre-wrap">{p.forensics}</pre>
                                                        </div>
                                                    )}
                                                </div>
                                            ))}

                                            {/* No open ports message */}
                                            {host.ports.filter(p => p.port > 0).length === 0 && (
                                                <div className="p-3 rounded-xl border border-border bg-muted/50 text-center">
                                                    <ShieldCheck className="w-5 h-5 mx-auto text-green-500 mb-1" />
                                                    <p className="text-xs text-muted-foreground">No open ports detected - Asset discovered via DNS only</p>
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Last Seen */}
                                    <p className="text-[10px] text-muted-foreground">
                                        Last scanned: {new Date(host.lastSeen).toLocaleString()}
                                    </p>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>

            {/* Footer Info */}
            <div className="p-4 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-3">
                <Info className="w-5 h-5 text-primary shrink-0 mt-0.5" />
                <div>
                    <p className="font-bold text-sm text-primary">Attack Surface Intelligence</p>
                    <p className="text-xs text-primary/70 mt-1">
                        Assets are discovered through DNS enumeration, subdomain brute-forcing, SSL certificate analysis, and active port scanning. Click on any asset to expand details, or click a domain to initiate a targeted deep scan.
                    </p>
                </div>
            </div>
        </div>
    );
}
