"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { LayoutDashboard, ShieldAlert, ScanSearch, CalendarClock, Globe, Target, Crosshair } from 'lucide-react';
import { PayIncLogo } from '@/components/ui';
import axios from 'axios';

const navItems = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Engagements', href: '/engagements', icon: Target },
    { name: 'Scenarios', href: '/scenarios', icon: Crosshair },
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
            return <span className="rounded-full bg-secondary px-2 py-0.5 text-xs font-semibold tabular-nums text-white" title="Running scans">{runningScans}</span>;
        }
        if (href === '/findings' && priorityFindings > 0) {
            // The one Yellow highlight in the layout.
            return <span className="rounded-full bg-payinc-yellow px-2 py-0.5 text-xs font-semibold tabular-nums text-payinc-dark-blue" title="Critical and high findings">{priorityFindings}</span>;
        }
        return null;
    };

    return (
        <aside className="z-40 flex bg-primary text-white lg:fixed lg:inset-y-0 lg:left-0 lg:w-64 lg:flex-col">
            <div className="flex shrink-0 items-center px-5 py-3 lg:block lg:px-6 lg:pb-6 lg:pt-8">
                <PayIncLogo onDark className="h-[45px] w-auto" />
                <p className="mt-4 hidden text-base font-semibold lg:block">Security Validation</p>
                <p className="hidden text-sm text-white/80 lg:block">Attack simulation and attack surface</p>
            </div>

            <nav aria-label="Main" className="flex flex-1 items-center gap-1 overflow-x-auto px-2 lg:flex-col lg:items-stretch lg:overflow-visible lg:px-4">
                {navItems.map((item) => {
                    const isActive = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            aria-current={isActive ? 'page' : undefined}
                            className={`flex shrink-0 items-center justify-between gap-3 rounded-full px-4 py-2.5 text-sm transition-colors ${isActive
                                ? 'bg-white font-semibold text-primary'
                                : 'font-normal text-white hover:bg-white/15'
                                }`}
                        >
                            <span className="flex items-center gap-3">
                                <item.icon className="h-4 w-4" aria-hidden />
                                {item.name}
                            </span>
                            {badgeFor(item.href)}
                        </Link>
                    );
                })}
            </nav>

            <p className="hidden p-6 text-xs leading-relaxed text-white/80 lg:block">
                Only scan systems you own or are authorised to test.
            </p>
        </aside>
    );
}
