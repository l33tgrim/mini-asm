import { NextResponse } from 'next/server';
import { runScenario, runPlaybook } from '@/lib/engine/runner';
import { loadEngagementContext, persistRun } from '@/lib/engine/persist';
import type { Mode } from '@/lib/engine/types';

export const maxDuration = 300;

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    try {
        const { scenarioId, playbookId, target, mode } = await req.json();
        if (!target) return NextResponse.json({ error: 'target is required' }, { status: 400 });
        if (!scenarioId && !playbookId) {
            return NextResponse.json({ error: 'scenarioId or playbookId is required' }, { status: 400 });
        }

        const { eng } = await loadEngagementContext(engagementId, mode as Mode | undefined, 'web');

        if (playbookId) {
            const result = await runPlaybook(playbookId, target, eng);
            for (const r of result.runs) await persistRun(engagementId, r, playbookId);
            return NextResponse.json(result);
        }

        const result = await runScenario(scenarioId, target, eng);
        await persistRun(engagementId, result);
        return NextResponse.json(result);
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}
