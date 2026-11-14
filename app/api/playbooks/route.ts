import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { listPlaybooks } from '@/lib/engine/registry';
import { parsePlaybookInput } from '@/lib/engine/playbook-input';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

// Lists built-in playbooks and user-defined custom playbooks together.
export async function GET() {
    try {
        const custom = await prisma.customPlaybook.findMany({
            orderBy: { createdAt: 'desc' },
            include: { steps: { orderBy: { order: 'asc' } } },
        });
        return NextResponse.json({ builtIn: listPlaybooks(), custom });
    } catch (error) {
        return handleError('GET /api/playbooks', error);
    }
}

export async function POST(req: Request) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);
    try {
        const { steps, name, ...fields } = parsePlaybookInput(body, true);
        const pb = await prisma.customPlaybook.create({
            data: { name: name!, ...fields, steps: { create: steps! } },
            include: { steps: { orderBy: { order: 'asc' } } },
        });
        return NextResponse.json(pb, { status: 201 });
    } catch (error) {
        return handleError('POST /api/playbooks', error);
    }
}
