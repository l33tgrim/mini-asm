import type { LucideIcon } from 'lucide-react';
import { AlertCircle } from 'lucide-react';
import { scanStatus, severityBadge } from '@/lib/ui';

export function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
    return (
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
                <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
                <p className="mt-1 text-sm text-muted-foreground">{description}</p>
            </div>
            {children && <div className="flex items-center gap-2">{children}</div>}
        </div>
    );
}

export function StatCard({ label, value, icon: Icon, tone = 'text-foreground' }: { label: string; value: number | string; icon: LucideIcon; tone?: string }) {
    return (
        <div className="rounded-xl border border-border bg-card p-4">
            <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-muted-foreground">{label}</p>
                <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
            </div>
            <p className={`mt-2 text-2xl font-semibold tabular-nums ${tone}`}>{value}</p>
        </div>
    );
}

const badgeBase = 'inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide';

export function SeverityBadge({ severity }: { severity: string }) {
    return <span className={`${badgeBase} ${severityBadge[severity] ?? severityBadge.INFO}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
    const { label, badge } = scanStatus(status);
    return <span className={`${badgeBase} ${badge}`}>{label}</span>;
}

export function ErrorBanner({ message }: { message: string | null }) {
    if (!message) return null;
    return (
        <div role="alert" className="flex items-start gap-2 rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            <span>{message}</span>
        </div>
    );
}

export function IconButton({ label, children, className = '', ...props }: { label: string } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
    return (
        <button
            type="button"
            aria-label={label}
            title={label}
            className={`rounded-lg border border-border p-2 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50 ${className}`}
            {...props}
        >
            {children}
        </button>
    );
}
