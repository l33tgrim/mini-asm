import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { nextRunAfter } from '@/lib/scheduler';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

type Context = { params: Promise<{ id: string }> };

export async function PATCH(req: Request, { params }: Context) {
    const body = await readJsonBody(req);
    if (!body || typeof body.active !== 'boolean') return errorResponse('"active" must be true or false.', 400);

    try {
        const { id } = await params;
        const existing = await prisma.schedule.findUnique({ where: { id } });
        if (!existing) return errorResponse('Schedule not found.', 404);

        // Re-enabling a schedule that fell overdue while paused should not fire it immediately.
        const overdue = existing.nextRun.getTime() < Date.now();
        const schedule = await prisma.schedule.update({
            where: { id },
            data: {
                active: body.active,
                ...(body.active && overdue ? { nextRun: nextRunAfter(existing.frequency) } : {}),
            },
        });
        return NextResponse.json(schedule);
    } catch (error) {
        return handleError('PATCH /api/schedules/[id]', error);
    }
}

export async function DELETE(_req: Request, { params }: Context) {
    try {
        const { id } = await params;
        const { count } = await prisma.schedule.deleteMany({ where: { id } });
        if (count === 0) return errorResponse('Schedule not found.', 404);
        return new NextResponse(null, { status: 204 });
    } catch (error) {
        return handleError('DELETE /api/schedules/[id]', error);
    }
}
