import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { parsePlaybookInput } from '@/lib/engine/playbook-input';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

type Context = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Context) {
    try {
        const { id } = await params;
        const pb = await prisma.customPlaybook.findUnique({ where: { id }, include: { steps: { orderBy: { order: 'asc' } } } });
        if (!pb) return errorResponse('Playbook not found.', 404);
        return NextResponse.json(pb);
    } catch (error) {
        return handleError('GET /api/playbooks/[id]', error);
    }
}

// Replace the playbook's fields and, when given, its steps in one transaction.
export async function PATCH(req: Request, { params }: Context) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    try {
        const { id } = await params;
        const { steps, ...fields } = parsePlaybookInput(body, false);
        if (!(await prisma.customPlaybook.findUnique({ where: { id }, select: { id: true } }))) {
            return errorResponse('Playbook not found.', 404);
        }
        const pb = await prisma.$transaction(async (tx) => {
            if (steps) await tx.playbookStep.deleteMany({ where: { playbookId: id } });
            return tx.customPlaybook.update({
                where: { id },
                data: { ...fields, ...(steps ? { steps: { create: steps } } : {}) },
                include: { steps: { orderBy: { order: 'asc' } } },
            });
        });
        return NextResponse.json(pb);
    } catch (error) {
        return handleError('PATCH /api/playbooks/[id]', error);
    }
}

export async function DELETE(_req: Request, { params }: Context) {
    try {
        const { id } = await params;
        const { count } = await prisma.customPlaybook.deleteMany({ where: { id } });
        if (count === 0) return errorResponse('Playbook not found.', 404);
        return NextResponse.json({ ok: true });
    } catch (error) {
        return handleError('DELETE /api/playbooks/[id]', error);
    }
}
