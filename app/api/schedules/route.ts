import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

// Previously the Schedules page called this route and it did not exist.
// This implements the CRUD the page expects. A separate worker (see
// scripts/schedule-worker.ts) is what actually fires due schedules.

export async function GET() {
    const schedules = await prisma.schedule.findMany({ orderBy: { nextRun: 'asc' } });
    return NextResponse.json(schedules);
}

function nextRunFrom(frequency: string): Date {
    const now = new Date();
    const next = new Date(now);
    if (frequency === 'WEEKLY') next.setDate(now.getDate() + 7);
    else next.setDate(now.getDate() + 1); // DAILY default
    return next;
}

export async function POST(req: Request) {
    try {
        const { target, frequency } = await req.json();
        if (!target) return NextResponse.json({ error: 'target is required' }, { status: 400 });
        const schedule = await prisma.schedule.create({
            data: {
                target,
                frequency: frequency === 'WEEKLY' ? 'WEEKLY' : 'DAILY',
                nextRun: nextRunFrom(frequency),
                active: true,
            },
        });
        return NextResponse.json(schedule);
    } catch (e) {
        return NextResponse.json({ error: (e as Error).message }, { status: 500 });
    }
}

export async function PATCH(req: Request) {
    const { id, active } = await req.json();
    if (!id) return NextResponse.json({ error: 'id required' }, { status: 400 });
    const schedule = await prisma.schedule.update({ where: { id }, data: { active: !!active } });
    return NextResponse.json(schedule);
}

export async function DELETE(req: Request) {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');
    if (!id) return NextResponse.json({ error: 'id required' }, { status: 400 });
    await prisma.schedule.delete({ where: { id } });
    return NextResponse.json({ ok: true });
}
