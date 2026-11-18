/**
 * Groups per-host findings into one entry per issue, the way a risk register lists
 * "SNMP port open" once with the assets it affects, instead of one card per IP.
 */

export interface GroupableFinding {
    id: string;
    ip: string;
    port: number;
    protocol?: string;
    service: string | null;
    severity: string;
    description: string | null;
    vulnerability: string | null;
    remediation: string | null;
    updatedAt: string;
    closedAt?: string | null;
}

export interface CountedText {
    text: string;
    /** How many hosts in the group report it. */
    hosts: number;
}

export interface FindingGroup<F extends GroupableFinding> {
    key: string;
    service: string;
    port: number;
    protocol: string;
    severity: string;
    description: string | null;
    issues: CountedText[];
    remediations: CountedText[];
    findings: F[];
    lastSeen: string;
}

const RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

function counted(values: string[]): CountedText[] {
    const map = new Map<string, number>();
    for (const v of values) map.set(v, (map.get(v) ?? 0) + 1);
    return [...map].map(([text, hosts]) => ({ text, hosts })).sort((a, b) => b.hosts - a.hosts);
}

const split = (value: string | null) => (value || '').split(';').map((v) => v.trim()).filter(Boolean);

export function groupFindings<F extends GroupableFinding>(findings: F[]): FindingGroup<F>[] {
    const groups = new Map<string, F[]>();
    for (const f of findings) {
        const protocol = f.protocol ?? 'tcp';
        const key = `${f.service ?? 'Unknown'}|${f.port}/${protocol}|${f.severity}`;
        const list = groups.get(key);
        if (list) list.push(f); else groups.set(key, [f]);
    }

    return [...groups].map(([key, list]) => {
        const first = list[0];
        const ipOrder = (ip: string) => ip.split('.').reduce((n, part) => n * 256 + Number(part || 0), 0);
        const sorted = [...list].sort((a, b) => ipOrder(a.ip) - ipOrder(b.ip));
        return {
            key,
            service: first.service ?? 'Unknown service',
            port: first.port,
            protocol: first.protocol ?? 'tcp',
            severity: first.severity,
            description: counted(list.map((f) => f.description).filter((d): d is string => !!d))[0]?.text ?? null,
            issues: counted(list.flatMap((f) => [...new Set(split(f.vulnerability))])),
            remediations: counted(list.map((f) => f.remediation?.trim()).filter((r): r is string => !!r)),
            findings: sorted,
            lastSeen: list.reduce((a, f) => (f.updatedAt > a ? f.updatedAt : a), first.updatedAt),
        };
    }).sort((a, b) =>
        (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) ||
        b.findings.length - a.findings.length ||
        a.port - b.port);
}
