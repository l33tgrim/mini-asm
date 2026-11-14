import { prisma } from '@/lib/prisma';
import type { EngagementContext, ScenarioRunOutput, PlaybookStepInput } from './runner';
import type { ScopeItem, ScopeKind } from '@/lib/safety/scope';
import type { Mode } from './types';
import { ScanError } from '@/lib/scan-runner';

/** Load a user-defined custom playbook into ordered, parameterized steps. */
export async function loadCustomPlaybook(
    id: string
): Promise<{ id: string; name: string; steps: PlaybookStepInput[] }> {
    const pb = await prisma.customPlaybook.findUnique({
        where: { id },
        include: { steps: { orderBy: { order: 'asc' } } },
    });
    if (!pb) throw new ScanError('Custom playbook not found.', 404);
    return {
        id: pb.id,
        name: pb.name,
        steps: pb.steps.map((s) => ({
            scenarioId: s.scenarioId,
            params: s.params ? (JSON.parse(s.params) as Record<string, unknown>) : {},
        })),
    };
}

/**
 * Build a gate context from a stored engagement. SAFE scenarios run against any
 * in-scope engagement; ACTIVE mode is refused unless the engagement has been
 * authorized.
 */
export async function loadEngagementContext(
    engagementId: string,
    modeOverride?: Mode,
    actor = 'cli'
): Promise<{ eng: EngagementContext; record: { id: string; name: string; status: string; mode: string } }> {
    const record = await prisma.engagement.findUnique({
        where: { id: engagementId },
        include: { scope: true },
    });
    if (!record) throw new ScanError('Engagement not found.', 404);

    // The engagement's own mode is the ceiling. A caller may ask for SAFE on an
    // ACTIVE engagement, but can never raise a SAFE engagement to ACTIVE per request.
    const mode: Mode = record.mode === 'ACTIVE' && modeOverride !== 'SAFE' ? 'ACTIVE' : 'SAFE';
    const authorized = ['AUTHORIZED', 'ACTIVE'].includes(record.status) && !record.revokedAt;

    const scope: ScopeItem[] = record.scope.map((s) => ({
        value: s.value,
        kind: s.kind as ScopeKind,
        verified: s.verified,
    }));

    return {
        eng: { engagementId: record.id, mode, scope, actor, authorized },
        record: { id: record.id, name: record.name, status: record.status, mode: record.mode },
    };
}

/** Persist a scenario run and its results. Returns the created run id. */
export async function persistRun(engagementId: string, output: ScenarioRunOutput, playbookId?: string): Promise<string> {
    const run = await prisma.scenarioRun.create({
        data: {
            engagementId,
            scenarioId: output.scenarioId,
            scenarioName: output.scenarioName,
            playbookId: playbookId || null,
            target: output.target,
            status: output.status,
            summary: output.summary,
            startedAt: new Date(),
            completedAt: new Date(),
            results: {
                create: output.results.map((r) => ({
                    title: r.title,
                    severity: r.severity,
                    outcome: r.outcome,
                    attckTactic: r.attckTactic || null,
                    attckTechnique: r.attckTechnique || null,
                    target: r.target || null,
                    evidence: r.evidence || null,
                    remediation: r.remediation || null,
                })),
            },
        },
    });
    return run.id;
}
