import { NextResponse } from 'next/server';
import { runScenario, runPlaybook, runSteps } from '@/lib/engine/runner';
import { getPlaybook, getScenario } from '@/lib/engine/registry';
import { loadEngagementContext, persistRun, loadCustomPlaybook } from '@/lib/engine/persist';
import { parseTarget } from '@/lib/targets';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

export const maxDuration = 300;

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    const { scenarioId, scenarioIds, playbookId, customPlaybookId } = body;

    try {
        const { id: engagementId } = await params;
        const target = parseTarget(body.target).value;
        const { eng } = await loadEngagementContext(engagementId, body.mode === 'SAFE' ? 'SAFE' : undefined, 'web');

        if (typeof customPlaybookId === 'string') {
            const pb = await loadCustomPlaybook(customPlaybookId);
            const runs = await runSteps(pb.steps, target, eng);
            for (const r of runs) await persistRun(engagementId, r, customPlaybookId);
            return NextResponse.json({ playbookId: pb.id, playbookName: pb.name, runs });
        }

        // A hand-picked set of scenarios, e.g. the ones suggested for an asset on the attack surface page.
        if (Array.isArray(scenarioIds)) {
            const ids = [...new Set(scenarioIds)];
            if (ids.length === 0 || ids.length > 30 || !ids.every((s) => typeof s === 'string' && getScenario(s))) {
                return errorResponse('scenarioIds must list between 1 and 30 known scenarios.', 400);
            }
            const runs = await runSteps(ids.map((s) => ({ scenarioId: s as string })), target, eng);
            for (const r of runs) await persistRun(engagementId, r);
            return NextResponse.json({ runs });
        }

        if (typeof playbookId === 'string') {
            if (!getPlaybook(playbookId)) return errorResponse('Unknown playbook.', 400);
            const result = await runPlaybook(playbookId, target, eng);
            for (const r of result.runs) await persistRun(engagementId, r, playbookId);
            return NextResponse.json(result);
        }

        if (typeof scenarioId !== 'string' || !getScenario(scenarioId)) {
            return errorResponse('A known scenarioId, playbookId or customPlaybookId is required.', 400);
        }
        const result = await runScenario(scenarioId, target, eng, {}, isRecord(body.params) ? body.params : {});
        await persistRun(engagementId, result);
        return NextResponse.json(result);
    } catch (error) {
        return handleError('POST /api/engagements/[id]/run', error);
    }
}
