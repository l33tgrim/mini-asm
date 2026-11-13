import { NextResponse } from 'next/server';
import { runScenario, runPlaybook, runSteps } from '@/lib/engine/runner';
import { loadEngagementContext, persistRun, loadCustomPlaybook } from '@/lib/engine/persist';
import type { Mode } from '@/lib/engine/types';

export const maxDuration = 300;

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    try {
        const { scenarioId, playbookId, customPlaybookId, target, mode, params: scenarioParams } = await req.json();
        if (!target) return NextResponse.json({ error: 'target is required' }, { status: 400 });
        if (!scenarioId && !playbookId && !customPlaybookId) {
            return NextResponse.json({ error: 'scenarioId, playbookId or customPlaybookId is required' }, { status: 400 });
        }

        const { eng } = await loadEngagementContext(engagementId, mode as Mode | undefined, 'web');

        if (customPlaybookId) {
            const pb = await loadCustomPlaybook(customPlaybookId);
            const runs = await runSteps(pb.steps, target, eng);
            for (const r of runs) await persistRun(engagementId, r, customPlaybookId);
            return NextResponse.json({ playbookId: pb.id, playbookName: pb.name, runs });
        }

        if (playbookId) {
            const result = await runPlaybook(playbookId, target, eng);
            for (const r of result.runs) await persistRun(engagementId, r, playbookId);
            return NextResponse.json(result);
        }

        const result = await runScenario(scenarioId, target, eng, {}, scenarioParams || {});
        await persistRun(engagementId, result);
        return NextResponse.json(result);
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}
