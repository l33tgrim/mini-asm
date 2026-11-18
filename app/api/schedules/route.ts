import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { parseTarget } from '@/lib/targets';
import { FREQUENCIES, nextRunAfter, type Frequency } from '@/lib/scheduler';
import { PortSpecError, parsePortSpec } from '@/lib/ports';
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

        if (body.ports !== undefined && body.ports !== null && typeof body.ports !== 'string') {
            return errorResponse('ports must be a string such as "default, 8000-8100".', 400);
        }
        if (body.udp !== undefined && typeof body.udp !== 'boolean') return errorResponse('udp must be true or false.', 400);
        const portSpec = typeof body.ports === 'string' && body.ports.trim() ? body.ports.trim() : null;
        try {
            parsePortSpec(portSpec);
        } catch (error) {
            if (error instanceof PortSpecError) return errorResponse(error.message, 400);
            throw error;
        }
        const udp = body.udp ?? true;

        if (await prisma.schedule.findFirst({ where: { target, frequency, portSpec } })) {
            return errorResponse('A schedule with that target, ports and frequency already exists.', 409);
        }
        if ((await prisma.schedule.count()) >= MAX_SCHEDULES) {
            return errorResponse(`No more than ${MAX_SCHEDULES} schedules are allowed.`, 400);
        }

        const schedule = await prisma.schedule.create({
            data: { target, frequency, portSpec, udp, nextRun: nextRunAfter(frequency) },
        });
        return NextResponse.json(schedule, { status: 201 });
    } catch (error) {
        return handleError('POST /api/schedules', error);
    }
}
