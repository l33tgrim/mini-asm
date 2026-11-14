"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { LayoutDashboard, ShieldAlert, ScanSearch, CalendarClock, Globe, Shield } from 'lucide-react';
import axios from 'axios';

const navItems = [
    { name: 'Overview', href: '/', icon: LayoutDashboard },
    { name: 'Scans', href: '/scans', icon: ScanSearch },
    { name: 'Findings', href: '/findings', icon: ShieldAlert },
    { name: 'Attack surface', href: '/attack-surface', icon: Globe },
    { name: 'Schedules', href: '/schedules', icon: CalendarClock },
];

export default function Sidebar() {
    const pathname = usePathname();
    const [runningScans, setRunningScans] = useState(0);
    const [priorityFindings, setPriorityFindings] = useState(0);

    useEffect(() => {
        let cancelled = false;
        const fetchStats = async () => {
            try {
                const { data } = await axios.get('/api/stats');
                if (cancelled) return;
                setRunningScans(data.runningScans ?? 0);
                setPriorityFindings((data.severity?.CRITICAL ?? 0) + (data.severity?.HIGH ?? 0));
            } catch {
                // The badges are a convenience. Pages report their own load errors.
            }
        };
        fetchStats();
        const interval = setInterval(fetchStats, 15000);
        return () => {
            cancelled = true;
            clearInterval(interval);
        };
    }, []);

    const badgeFor = (href: string) => {
        if (href === '/scans' && runningScans > 0) {
            return <span className="rounded-md bg-primary/15 px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-primary" title="Running scans">{runningScans}</span>;
        }
        if (href === '/findings' && priorityFindings > 0) {
            return <span className="rounded-md bg-sev-critical/15 px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-sev-critical" title="Critical and high findings">{priorityFindings}</span>;
        }
        return null;
    };

    return (
        <aside className="z-40 flex border-b border-border bg-card lg:fixed lg:inset-y-0 lg:left-0 lg:w-60 lg:flex-col lg:border-b-0 lg:border-r">
            <div className="flex items-center gap-3 px-4 py-3 lg:border-b lg:border-border lg:px-5 lg:py-5">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
                    <Shield className="h-5 w-5 text-primary-foreground" aria-hidden />
                </div>
                <div className="hidden sm:block">
                    <p className="text-sm font-semibold leading-tight">Mini ASM</p>
                    <p className="text-xs text-muted-foreground">Attack surface management</p>
                </div>
            </div>

            <nav aria-label="Main" className="flex flex-1 items-center gap-1 overflow-x-auto px-2 lg:flex-col lg:items-stretch lg:overflow-visible lg:p-3">
                {navItems.map((item) => {
                    const isActive = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            aria-current={isActive ? 'page' : undefined}
                            className={`flex shrink-0 items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${isActive
                                ? 'bg-primary/15 text-foreground'
                                : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                                }`}
                        >
                            <span className="flex items-center gap-3">
                                <item.icon className={`h-4 w-4 ${isActive ? 'text-primary' : ''}`} aria-hidden />
                                {item.name}
                            </span>
                            {badgeFor(item.href)}
                        </Link>
                    );
                })}
            </nav>

            <p className="hidden border-t border-border p-4 text-xs leading-relaxed text-muted-foreground lg:block">
                Only scan systems you own or are authorised to test.
            </p>
        </aside>
    );
}
