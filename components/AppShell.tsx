'use client';

import { usePathname } from 'next/navigation';
import Sidebar from '@/components/Sidebar';

/** The sign-in page stands alone; every other page gets the sidebar layout. */
export default function AppShell({ children }: { children: React.ReactNode }) {
    if (usePathname() === '/login') return <>{children}</>;
    return (
        <>
            <Sidebar />
            <main className="min-h-screen lg:pl-64">
                <div className="mx-auto max-w-7xl p-5 sm:p-8">{children}</div>
            </main>
        </>
    );
}
