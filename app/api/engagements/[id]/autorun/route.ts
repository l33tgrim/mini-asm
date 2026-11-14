import { NextResponse } from 'next/server';
import { runAutopilot } from '@/lib/engine/autopilot';
import { loadEngagementContext, persistRun } from '@/lib/engine/persist';
import { parseTarget } from '@/lib/targets';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

export const maxDuration = 300;

// Autonomous assessment: recon, adaptive scenario plan, scoring, narrative.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);

    try {
        const { id: engagementId } = await params;
        const target = parseTarget(body.target).value;
        const { eng } = await loadEngagementContext(engagementId, body.mode === 'SAFE' ? 'SAFE' : undefined, 'web');
        const result = await runAutopilot(target, eng);
        for (const r of result.runs) await persistRun(engagementId, r, 'autopilot');
        return NextResponse.json({
            target: result.target,
            mode: result.mode,
            plannedBy: result.plannedBy,
            risk: result.risk,
            narrative: result.narrative,
        });
    } catch (error) {
        return handleError('POST /api/engagements/[id]/autorun', error);
    }
}
