import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { listPlaybooks } from '@/lib/engine/registry';

// Lists built-in playbooks and user-defined custom playbooks together.
export async function GET() {
    const custom = await prisma.customPlaybook.findMany({
        orderBy: { createdAt: 'desc' },
        include: { steps: { orderBy: { order: 'asc' } } },
    });
    return NextResponse.json({
        builtIn: listPlaybooks(),
        custom,
    });
}

interface StepInput {
    scenarioId: string;
    params?: unknown;
    order?: number;
}

export async function POST(req: Request) {
    try {
        const { name, description, threat, attckTactics, steps } = await req.json();
        if (!name) return NextResponse.json({ error: 'name is required' }, { status: 400 });
        const stepList: StepInput[] = Array.isArray(steps) ? steps : [];
        const pb = await prisma.customPlaybook.create({
            data: {
                name,
                description: description || null,
                threat: threat || null,
                attckTactics: Array.isArray(attckTactics) ? attckTactics.join(',') : attckTactics || null,
                steps: {
                    create: stepList.map((s, i) => ({
                        scenarioId: s.scenarioId,
                        order: s.order ?? i,
                        params: s.params ? JSON.stringify(s.params) : null,
                    })),
                },
            },
            include: { steps: true },
        });
        return NextResponse.json(pb);
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}
