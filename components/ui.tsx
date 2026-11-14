import type { LucideIcon } from 'lucide-react';
import { AlertCircle } from 'lucide-react';
import { scanStatus, severityBadge } from '@/lib/ui';

/** The PayInc wordmark, exactly as supplied in the brand manual. The dot is always Light Blue. */
export function PayIncLogo({ onDark = false, className = '' }: { onDark?: boolean; className?: string }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 483 203" role="img" aria-label="PayInc" className={className}>
            <path fill={onDark ? '#FFFFFF' : '#1D1A60'} fillRule="nonzero" d="M227.51 37.22 L246.72 0.22 C246.81 0.04 246.99 -0.07 247.19 -0.07 L276.73 -0.07 C277.14 -0.07 277.39 0.38 277.19 0.73 L240.75 63.46 C240.70 63.54 240.68 63.63 240.68 63.72 L240.68 86.56 C240.68 86.85 240.44 87.09 240.15 87.09 L214.39 87.09 C214.10 87.09 213.86 86.85 213.86 86.56 L213.86 63.72 C213.86 63.63 213.84 63.54 213.79 63.46 L177.35 0.73 C177.14 0.38 177.40 -0.07 177.81 -0.07 L207.35 -0.07 C207.54 -0.07 207.73 0.04 207.82 0.22 L227.03 37.22 C227.13 37.41 227.41 37.41 227.51 37.22 Z M214.39 140.73 L240.15 140.73 C240.44 140.73 240.68 140.97 240.68 141.26 L240.68 200.54 C240.68 200.83 240.44 201.07 240.15 201.07 L214.39 201.07 C214.10 201.07 213.86 200.83 213.86 200.54 L213.86 141.26 C213.86 140.97 214.10 140.73 214.39 140.73 Z M335.90 87.09 L361.65 87.09 C361.95 87.09 362.18 87.33 362.18 87.62 L362.18 200.54 C362.18 200.83 361.95 201.07 361.65 201.07 L334.47 201.07 C334.29 201.07 334.12 200.97 334.02 200.82 L290.91 132.56 C290.77 132.33 290.42 132.43 290.42 132.70 L290.42 200.54 C290.42 200.83 290.18 201.07 289.88 201.07 L264.13 201.07 C263.84 201.07 263.60 200.83 263.60 200.54 L263.60 87.62 C263.60 87.33 263.84 87.09 264.13 87.09 L290.46 87.09 C290.64 87.09 290.81 87.18 290.91 87.34 L334.87 156.95 C335.02 157.18 335.37 157.07 335.37 156.81 L335.37 87.62 C335.37 87.33 335.60 87.09 335.90 87.09 Z M407.95 195.77 C399.02 191.22 391.90 184.56 386.60 175.78 C381.31 167.01 378.66 156.58 378.66 144.48 C378.66 133.46 380.98 123.48 385.64 114.54 C390.30 105.61 397.04 98.54 405.87 93.35 C414.70 88.16 425.21 85.57 437.41 85.57 C445.65 85.57 453.87 87.39 462.05 91.02 C470.09 94.60 477.07 99.97 482.99 107.15 C483.17 107.37 483.14 107.71 482.92 107.90 L463.98 123.91 C463.76 124.10 463.43 124.07 463.24 123.85 C460.19 120.28 456.48 117.29 452.10 114.86 C447.55 112.35 442.65 111.09 437.41 111.09 C431.74 111.09 426.58 112.43 421.92 115.10 C417.27 117.78 413.57 121.63 410.84 126.66 C408.11 131.69 406.75 137.63 406.75 144.48 C406.75 150.48 408.03 155.93 410.60 160.85 C413.17 165.78 416.78 169.68 421.44 172.57 C426.09 175.46 431.42 176.91 437.41 176.91 C442.44 176.91 447.28 175.70 451.94 173.30 C456.43 170.98 460.19 167.98 463.24 164.32 C463.43 164.09 463.76 164.06 463.99 164.26 L482.93 180.42 C483.15 180.61 483.18 180.94 482.99 181.17 C477.80 187.51 471.36 192.64 463.66 196.57 C455.79 200.59 447.04 202.59 437.41 202.59 C426.71 202.59 416.89 200.32 407.95 195.77 Z M52.09 49.62 C48.88 52.24 44.33 53.55 38.44 53.55 L27.74 53.55 C27.44 53.55 27.20 53.31 27.20 53.02 L27.20 24.06 C27.20 23.77 27.44 23.53 27.74 23.53 L38.76 23.53 C44.65 23.53 49.14 24.92 52.25 27.70 C55.35 30.49 56.90 34.12 56.90 38.62 C56.90 43.33 55.30 47.00 52.09 49.62 Z M74.48 10.69 C67.68 3.52 57.54 -0.07 44.06 -0.07 L0.92 -0.07 C0.62 -0.07 0.39 0.17 0.39 0.46 L0.39 113.38 C0.39 113.67 0.62 113.91 0.92 113.91 L26.67 113.91 C26.97 113.91 27.20 113.67 27.20 113.38 L27.20 77.68 C27.20 77.39 27.44 77.15 27.74 77.15 L41.97 77.15 C55.14 77.15 65.54 73.94 73.20 67.52 C80.85 61.09 84.67 51.68 84.67 39.26 C84.67 27.38 81.28 17.86 74.48 10.69 Z M123.89 70.73 C123.53 70.73 123.27 70.37 123.38 70.03 L135.59 32.15 C135.67 31.91 136.01 31.91 136.09 32.15 L148.30 70.03 C148.41 70.37 148.15 70.73 147.79 70.73 L123.89 70.73 Z M148.97 0.28 C148.89 0.07 148.69 -0.07 148.47 -0.07 L135.84 -0.07 L123.21 -0.07 C122.99 -0.07 122.79 0.07 122.71 0.28 L81.36 113.19 C81.23 113.54 81.49 113.91 81.86 113.91 L108.80 113.91 C109.04 113.91 109.24 113.76 109.31 113.54 L115.66 93.89 C115.73 93.67 115.93 93.52 116.16 93.52 L135.84 93.52 L155.52 93.52 C155.75 93.52 155.95 93.67 156.02 93.89 L162.37 113.54 C162.44 113.76 162.64 113.91 162.87 113.91 L189.82 113.91 C190.19 113.91 190.44 113.54 190.32 113.19 L148.97 0.28 Z" />
            <path fill="#007AFF" d="M227.27 100.50 L227.27 100.50 C234.68 100.50 240.68 106.50 240.68 113.91 L240.68 113.91 C240.68 121.32 234.68 127.32 227.27 127.32 C219.86 127.32 213.86 121.32 213.86 113.91 L213.86 113.91 C213.86 106.50 219.86 100.50 227.27 100.50 Z" />
        </svg>
    );
}

export function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
    return (
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
                <h1 className="text-3xl font-bold">{title}</h1>
                <p className="mt-1 text-sm text-muted-foreground">{description}</p>
            </div>
            {children && <div className="flex items-center gap-2">{children}</div>}
        </div>
    );
}

export function StatCard({ label, value, icon: Icon, tone = 'text-foreground' }: { label: string; value: number | string; icon: LucideIcon; tone?: string }) {
    return (
        <div className="rounded-2xl border border-border bg-card p-5">
            <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-muted-foreground">{label}</p>
                <span className="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-white" aria-hidden>
                    <Icon className="h-4 w-4" />
                </span>
            </div>
            <p className={`mt-1 text-3xl font-bold tabular-nums ${tone}`}>{value}</p>
        </div>
    );
}

const badgeBase = 'inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide';

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
        <div role="alert" className="flex items-start gap-2 rounded-lg border border-sev-critical bg-sev-critical/10 px-3 py-2 text-sm font-normal text-foreground">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" aria-hidden />
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
            className={`rounded-full border border-border p-2 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50 ${className}`}
            {...props}
        >
            {children}
        </button>
    );
}
