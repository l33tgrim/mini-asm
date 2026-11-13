import { NextResponse } from 'next/server';
import { runAutopilot } from '@/lib/engine/autopilot';
import { loadEngagementContext, persistRun } from '@/lib/engine/persist';
import type { Mode } from '@/lib/engine/types';

export const maxDuration = 300;

// Autonomous AI assessment: recon, adaptive scenario plan, scoring, narrative.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id: engagementId } = await params;
    try {
        const { target, mode } = await req.json();
        if (!target) return NextResponse.json({ error: 'target is required' }, { status: 400 });
        const { eng } = await loadEngagementContext(engagementId, mode as Mode | undefined, 'web');
        const result = await runAutopilot(target, eng);
        for (const r of result.runs) await persistRun(engagementId, r, 'autopilot');
        return NextResponse.json({
            target: result.target,
            mode: result.mode,
            plannedBy: result.plannedBy,
            risk: result.risk,
            narrative: result.narrative,
        });
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}
