import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { handleError } from '@/lib/api';
import { scoreResults } from '@/lib/report/risk';
import { listScenarios } from '@/lib/engine/registry';
import type { ScenarioResult, Severity, Outcome } from '@/lib/engine/types';

export async function GET() {
  try {
    const [engagementCount, runCount, rawResults, recentRuns] = await Promise.all([
        prisma.engagement.count(),
        prisma.scenarioRun.count(),
        prisma.scenarioResult.findMany({ select: { severity: true, outcome: true, attckTactic: true } }),
        prisma.scenarioRun.findMany({
            orderBy: { createdAt: 'desc' },
            take: 8,
            include: { engagement: { select: { name: true } }, _count: { select: { results: true } } },
        }),
    ]);

    const results = rawResults.map((r) => ({
        title: '', severity: r.severity as Severity, outcome: r.outcome as Outcome, attckTactic: r.attckTactic || undefined,
    })) as ScenarioResult[];

    const risk = scoreResults(results);

    // ATT&CK tactic coverage: tactics exercised vs tactics the catalog can cover.
    const catalogTactics = new Set(listScenarios().map((s) => s.attckTactic).filter(Boolean) as string[]);
    const testedTactics = new Set(results.filter((r) => r.attckTactic).map((r) => r.attckTactic as string));

    const severity = {
        CRITICAL: risk.counts.CRITICAL,
        HIGH: risk.counts.HIGH,
        MEDIUM: risk.counts.MEDIUM,
        LOW: risk.counts.LOW,
    };

    return NextResponse.json({
        engagementCount,
        runCount,
        scenarioCount: listScenarios().length,
        posture: { score: risk.score, grade: risk.grade, proven: risk.proven, vulnerable: risk.vulnerable, headline: risk.headline },
        severity,
        attack: {
            tested: Array.from(testedTactics),
            catalog: Array.from(catalogTactics),
            coveragePct: catalogTactics.size ? Math.round((testedTactics.size / catalogTactics.size) * 100) : 0,
        },
        recent: recentRuns.map((r) => ({
            id: r.id,
            engagementId: r.engagementId,
            engagement: r.engagement?.name,
            scenario: r.scenarioName,
            target: r.target,
            status: r.status,
            results: r._count.results,
            createdAt: r.createdAt,
        })),
    });
  } catch (error) {
        return handleError('GET /api/dashboard', error);
    }
}
