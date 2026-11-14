// Shared presentation helpers so severity and status look the same on every page.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export const severityBadge: Record<string, string> = {
    CRITICAL: 'text-sev-critical bg-sev-critical/10 border-sev-critical/30',
    HIGH: 'text-sev-high bg-sev-high/10 border-sev-high/30',
    MEDIUM: 'text-sev-medium bg-sev-medium/10 border-sev-medium/30',
    LOW: 'text-sev-low bg-sev-low/10 border-sev-low/30',
    INFO: 'text-sev-info bg-sev-info/10 border-sev-info/30',
};

export const severityText: Record<string, string> = {
    CRITICAL: 'text-sev-critical',
    HIGH: 'text-sev-high',
    MEDIUM: 'text-sev-medium',
    LOW: 'text-sev-low',
    INFO: 'text-sev-info',
};

export const severityBar: Record<string, string> = {
    CRITICAL: 'bg-sev-critical',
    HIGH: 'bg-sev-high',
    MEDIUM: 'bg-sev-medium',
    LOW: 'bg-sev-low',
    INFO: 'bg-sev-info',
};

export const severityLabel = (s: string) => s.charAt(0) + s.slice(1).toLowerCase();

const STATUS: Record<string, { label: string; badge: string }> = {
    PENDING: { label: 'Pending', badge: 'text-sev-info bg-sev-info/10 border-sev-info/30' },
    RUNNING: { label: 'Running', badge: 'text-primary bg-primary/10 border-primary/30' },
    COMPLETED: { label: 'Completed', badge: 'text-success bg-success/10 border-success/30' },
    FAILED: { label: 'Failed', badge: 'text-sev-critical bg-sev-critical/10 border-sev-critical/30' },
    TIMED_OUT: { label: 'Timed out', badge: 'text-sev-high bg-sev-high/10 border-sev-high/30' },
    INTERRUPTED: { label: 'Interrupted', badge: 'text-sev-medium bg-sev-medium/10 border-sev-medium/30' },
};

export const scanStatus = (status: string) => STATUS[status] ?? { label: status, badge: STATUS.PENDING.badge };

/** Pulls the server's error message out of a failed axios call. */
export function apiError(error: unknown, fallback: string): string {
    const message = (error as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
    return typeof message === 'string' && message ? message : fallback;
}

export const formatDateTime = (value: string | Date) =>
    new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function formatDuration(totalSeconds: number): string {
    const s = Math.max(0, Math.floor(totalSeconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = (s % 60).toString().padStart(2, '0');
    return h > 0 ? `${h}:${m.toString().padStart(2, '0')}:${sec}` : `${m}:${sec}`;
}
