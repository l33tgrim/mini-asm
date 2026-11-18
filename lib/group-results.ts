/**
 * Groups scenario results from an engagement into one entry per issue, the
 * same way findings are grouped elsewhere: "Missing security headers" once,
 * with the hosts it affects, instead of once per run.
 */

export interface GroupableResult {
    id: string;
    title: string;
    severity: string;
    outcome: string;
    attckTactic?: string;
    attckTechnique?: string;
    target?: string;
    evidence?: string;
    remediation?: string;
}

export interface GroupableRun<R extends GroupableResult> {
    id: string;
    scenarioName: string;
    target: string;
    createdAt: string;
    results: R[];
}

export interface ResultGroup<R extends GroupableResult> {
    key: string;
    title: string;
    scenarioName: string;
    severity: string;
    outcome: string;
    attckTactic?: string;
    attckTechnique?: string;
    remediation?: string;
    items: { target: string; result: R; at: string }[];
}

const SEVERITY: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const OUTCOME: Record<string, number> = { PROVEN: 4, VULNERABLE: 3, ERROR: 2, INFO: 1, SECURE: 0 };

/** Outcomes that need attention. The rest are passed checks and notes. */
export const ACTIONABLE = new Set(['PROVEN', 'VULNERABLE', 'ERROR']);

/**
 * Removes the host part of a title so the same issue on two hosts lines up:
 * "Weak cookie attributes on www.a.com:443" becomes "Weak cookie attributes".
 */
export function issueTitle(title: string): string {
    return title
        .replace(/\s+(?:on|at|for|by)\s+\[?[a-z0-9-]+(?:\.[a-z0-9-]+)+\]?(?::\d+)?(?=$|[\s)])/gi, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
}

export function groupResults<R extends GroupableResult>(runs: GroupableRun<R>[]): ResultGroup<R>[] {
    // A rerun of the same scenario on the same target replaces the older run.
    const latest = new Map<string, GroupableRun<R>>();
    for (const run of runs) {
        const key = `${run.scenarioName}|${run.target}`;
        const seen = latest.get(key);
        if (!seen || run.createdAt > seen.createdAt) latest.set(key, run);
    }

    const groups = new Map<string, ResultGroup<R>>();
    for (const run of latest.values()) {
        for (const result of run.results) {
            const title = issueTitle(result.title) || result.title;
            const key = `${run.scenarioName}|${title}|${result.severity}|${result.outcome}`;
            let group = groups.get(key);
            if (!group) {
                group = {
                    key, title, scenarioName: run.scenarioName, severity: result.severity, outcome: result.outcome,
                    attckTactic: result.attckTactic, attckTechnique: result.attckTechnique, remediation: result.remediation, items: [],
                };
                groups.set(key, group);
            }
            const target = result.target || run.target;
            if (!group.items.some((i) => i.target === target && i.result.evidence === result.evidence)) {
                group.items.push({ target, result, at: run.createdAt });
            }
        }
    }

    return [...groups.values()]
        .map((g) => ({ ...g, items: g.items.sort((a, b) => a.target.localeCompare(b.target)) }))
        .sort((a, b) =>
            (OUTCOME[b.outcome] ?? 0) - (OUTCOME[a.outcome] ?? 0) ||
            (SEVERITY[b.severity] ?? 0) - (SEVERITY[a.severity] ?? 0) ||
            b.items.length - a.items.length ||
            a.title.localeCompare(b.title));
}
