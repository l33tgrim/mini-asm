// Shared presentation helpers so severity and status look the same on every page.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// Filled chips, each pairing checked for contrast (Dark Blue on orange 8:1, white on the dark blues 7:1+).
export const severityBadge: Record<string, string> = {
    CRITICAL: 'bg-sev-critical text-foreground border-sev-critical',
    HIGH: 'bg-sev-high text-white border-sev-high',
    MEDIUM: 'bg-sev-medium text-white border-sev-medium',
    LOW: 'bg-border text-foreground border-border',
    INFO: 'bg-card text-muted-foreground border-border',
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
    PENDING: { label: 'Pending', badge: 'bg-card text-muted-foreground border-border' },
    RUNNING: { label: 'Running', badge: 'bg-border text-foreground border-border' },
    COMPLETED: { label: 'Completed', badge: 'bg-sev-medium text-white border-sev-medium' },
    FAILED: { label: 'Failed', badge: 'bg-sev-critical text-foreground border-sev-critical' },
    TIMED_OUT: { label: 'Timed out', badge: 'bg-card text-foreground border-sev-critical' },
    INTERRUPTED: { label: 'Interrupted', badge: 'bg-card text-foreground border-sev-critical' },
};

export const scanStatus = (status: string) => STATUS[status] ?? { label: status, badge: STATUS.PENDING.badge };

/** Pulls the server's error message out of a failed axios call. */
export function apiError(error: unknown, fallback: string): string {
    const message = (error as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
    return typeof message === 'string' && message ? message : fallback;
}

/** "443" for TCP, "123/udp" for UDP, so the two never look like the same port. */
export const portLabel = (port: number, protocol?: string | null) => (protocol === 'udp' ? `${port}/udp` : String(port));

export const formatDateTime = (value: string | Date) =>
    new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function formatDuration(totalSeconds: number): string {
    const s = Math.max(0, Math.floor(totalSeconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = (s % 60).toString().padStart(2, '0');
    return h > 0 ? `${h}:${m.toString().padStart(2, '0')}:${sec}` : `${m}:${sec}`;
}

/** Link to the schedules page with the form filled in from a scan. */
export function scheduleHref(target: string, portSpec?: string | null, udp?: boolean): string {
    const params = new URLSearchParams({ target });
    if (portSpec) params.set('ports', portSpec);
    if (udp === false) params.set('udp', '0');
    return `/schedules?${params.toString()}`;
}
