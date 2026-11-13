"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import {
    LayoutDashboard, ShieldAlert, ScanSearch, Calendar, Settings,
    Activity, Globe, Shield, ChevronRight, Zap, Bell
} from 'lucide-react';
import axios from 'axios';

const navItems = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard, badge: null },
    { name: 'Engagements', href: '/engagements', icon: Shield, badge: null },
    { name: 'Scenarios', href: '/scenarios', icon: Zap, badge: null },
    { name: 'Scans', href: '/scans', icon: ScanSearch, badge: 'running' },
    { name: 'Findings', href: '/findings', icon: ShieldAlert, badge: 'count' },
    { name: 'Attack Surface', href: '/attack-surface', icon: Globe, badge: null },
    { name: 'Schedules', href: '/schedules', icon: Calendar, badge: null },
];

export default function Sidebar() {
    const pathname = usePathname();
    const [runningScans, setRunningScans] = useState(0);
    const [criticalFindings, setCriticalFindings] = useState(0);

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const [scansRes, findingsRes] = await Promise.all([
                    axios.get('/api/scans'),
                    axios.get('/api/findings')
                ]);
                setRunningScans(scansRes.data.filter((s: any) => s.status === 'RUNNING').length);
                setCriticalFindings(findingsRes.data.filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length);
            } catch (error) {
                console.error('Failed to fetch sidebar stats', error);
            }
        };
        fetchStats();
        const interval = setInterval(fetchStats, 10000);
        return () => clearInterval(interval);
    }, []);

    const getBadge = (item: typeof navItems[0]) => {
        if (item.badge === 'running' && runningScans > 0) {
            return (
                <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 text-[9px] font-black animate-pulse">
                    {runningScans}
                </span>
            );
        }
        if (item.badge === 'count' && criticalFindings > 0) {
            return (
                <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[9px] font-black">
                    {criticalFindings}
                </span>
            );
        }
        return null;
    };

    return (
        <div className="fixed left-0 top-0 h-full w-64 bg-card/80 backdrop-blur-xl border-r border-border flex flex-col z-50">
            {/* Logo */}
            <div className="p-6 border-b border-border">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl brand-gradient flex items-center justify-center shadow-lg shadow-primary/30">
                        <Shield className="text-white w-5 h-5" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black tracking-tight">PayInc</h1>
                        <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest">Security Validation</p>
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-1">
                <p className="text-[9px] uppercase tracking-widest text-muted-foreground font-bold mb-3 px-3">Main Menu</p>
                {navItems.map((item) => {
                    const isActive = pathname === item.href ||
                        (item.href !== '/' && pathname.startsWith(item.href));
                    const badge = getBadge(item);

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={`flex items-center justify-between px-3 py-2.5 rounded-xl transition-all duration-200 group ${isActive
                                    ? 'bg-primary text-primary-foreground shadow-lg shadow-primary/20'
                                    : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                                }`}
                        >
                            <div className="flex items-center gap-3">
                                <item.icon className="w-4 h-4" />
                                <span className="text-sm font-medium">{item.name}</span>
                            </div>
                            {badge || (
                                <ChevronRight className={`w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity ${isActive ? 'opacity-100' : ''
                                    }`} />
                            )}
                        </Link>
                    );
                })}
            </nav>

            {/* Bottom Section */}
            <div className="p-4 space-y-3 border-t border-border">
                {/* System Status */}
                <div className="p-3 rounded-xl bg-gradient-to-r from-green-500/5 to-emerald-500/5 border border-green-500/20">
                    <div className="flex items-center justify-between mb-2">
                        <p className="text-[9px] font-bold uppercase tracking-widest text-green-400">System Status</p>
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                    </div>
                    <div className="flex items-center gap-2">
                        <Activity className="w-3 h-3 text-green-500" />
                        <span className="text-xs font-medium text-green-400">All Systems Operational</span>
                    </div>
                </div>

                {/* Quick Stats */}
                <div className="grid grid-cols-2 gap-2">
                    <div className="p-2 rounded-lg bg-muted/50 text-center">
                        <p className="text-lg font-black">{runningScans}</p>
                        <p className="text-[8px] uppercase text-muted-foreground font-bold">Running</p>
                    </div>
                    <div className="p-2 rounded-lg bg-muted/50 text-center">
                        <p className="text-lg font-black text-red-400">{criticalFindings}</p>
                        <p className="text-[8px] uppercase text-muted-foreground font-bold">Priority</p>
                    </div>
                </div>

                {/* Settings Link */}
                <Link
                    href="/settings"
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${pathname === '/settings'
                            ? 'bg-accent text-foreground'
                            : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                        }`}
                >
                    <Settings className="w-4 h-4" />
                    <span className="text-sm font-medium">Settings</span>
                </Link>
            </div>
        </div>
    );
}
