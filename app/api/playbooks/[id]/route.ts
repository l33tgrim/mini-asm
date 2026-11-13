import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    const pb = await prisma.customPlaybook.findUnique({
        where: { id },
        include: { steps: { orderBy: { order: 'asc' } } },
    });
    if (!pb) return NextResponse.json({ error: 'not found' }, { status: 404 });
    return NextResponse.json(pb);
}

interface StepInput {
    scenarioId: string;
    params?: unknown;
    order?: number;
}

// Replace the playbook's fields and steps in one call.
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    const { name, description, threat, attckTactics, steps } = await req.json();
    const data: Record<string, unknown> = {};
    if (name !== undefined) data.name = name;
    if (description !== undefined) data.description = description;
    if (threat !== undefined) data.threat = threat;
    if (attckTactics !== undefined) data.attckTactics = Array.isArray(attckTactics) ? attckTactics.join(',') : attckTactics;

    if (Array.isArray(steps)) {
        await prisma.playbookStep.deleteMany({ where: { playbookId: id } });
        data.steps = {
            create: (steps as StepInput[]).map((s, i) => ({
                scenarioId: s.scenarioId,
                order: s.order ?? i,
                params: s.params ? JSON.stringify(s.params) : null,
            })),
        };
    }

    const pb = await prisma.customPlaybook.update({
        where: { id },
        data,
        include: { steps: { orderBy: { order: 'asc' } } },
    });
    return NextResponse.json(pb);
}

export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    await prisma.customPlaybook.delete({ where: { id } });
    return NextResponse.json({ ok: true });
}
