import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { parseTarget } from '@/lib/targets';
import { FREQUENCIES, nextRunAfter, type Frequency } from '@/lib/scheduler';
import { errorResponse, handleError, readJsonBody } from '@/lib/api';

const MAX_SCHEDULES = 50;

export async function GET() {
    try {
        const schedules = await prisma.schedule.findMany({ orderBy: { createdAt: 'desc' } });
        return NextResponse.json(schedules);
    } catch (error) {
        return handleError('GET /api/schedules', error);
    }
}

export async function POST(req: Request) {
    const body = await readJsonBody(req);
    if (!body) return errorResponse('Request body must be JSON.', 400);

    try {
        const target = parseTarget(body.target).value;
        if (!FREQUENCIES.includes(body.frequency as Frequency)) {
            return errorResponse('Frequency must be DAILY, WEEKLY or MONTHLY.', 400);
        }
        const frequency = body.frequency as Frequency;

        if (await prisma.schedule.findFirst({ where: { target, frequency } })) {
            return errorResponse('A schedule with that target and frequency already exists.', 409);
        }
        if ((await prisma.schedule.count()) >= MAX_SCHEDULES) {
            return errorResponse(`No more than ${MAX_SCHEDULES} schedules are allowed.`, 400);
        }

        const schedule = await prisma.schedule.create({
            data: { target, frequency, nextRun: nextRunAfter(frequency) },
        });
        return NextResponse.json(schedule, { status: 201 });
    } catch (error) {
        return handleError('POST /api/schedules', error);
    }
}
