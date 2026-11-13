import type { ScenarioResult, Severity } from '@/lib/engine/types';

const SEVERITY_WEIGHT: Record<Severity, number> = { INFO: 0, LOW: 3, MEDIUM: 8, HIGH: 20, CRITICAL: 40 };

export interface RiskScore {
    score: number; // 0 (worst) .. 100 (best / clean)
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    exposure: number; // raw weighted exposure points
    counts: Record<Severity, number>;
    proven: number;
    vulnerable: number;
    headline: string;
}

function grade(score: number): RiskScore['grade'] {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 55) return 'C';
    if (score >= 35) return 'D';
    return 'F';
}

/**
 * Posture score from a set of results. A proven (non-destructive) exploit
 * weighs heavier than an unproven weakness of the same severity, because it is
 * demonstrated, not theoretical. 100 is clean; the score falls as exposure rises.
 */
export function scoreResults(results: ScenarioResult[]): RiskScore {
    const counts: Record<Severity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    let exposure = 0;
    let proven = 0;
    let vulnerable = 0;

    for (const r of results) {
        if (r.outcome === 'VULNERABLE' || r.outcome === 'PROVEN') {
            counts[r.severity]++;
            const base = SEVERITY_WEIGHT[r.severity];
            exposure += r.outcome === 'PROVEN' ? base * 1.5 : base;
            if (r.outcome === 'PROVEN') proven++;
            else vulnerable++;
        }
    }

    // Diminishing-returns curve so a few criticals still tank the score but a
    // long tail of lows does not overflow it. A single proven critical lands
    // around grade D; accumulating weaknesses drives toward F.
    const score = Math.max(0, Math.round(100 * Math.exp(-exposure / 60)));

    const topSeverity = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).find((s) => counts[s] > 0);
    const headline = proven > 0
        ? `${proven} proven exploit${proven > 1 ? 's' : ''} and ${vulnerable} unproven weakness${vulnerable === 1 ? '' : 'es'}`
        : topSeverity
            ? `${counts[topSeverity]} ${topSeverity.toLowerCase()} and ${vulnerable} total weaknesses`
            : 'no weaknesses confirmed';

    return { score, grade: grade(score), exposure: Math.round(exposure), counts, proven, vulnerable, headline };
}
