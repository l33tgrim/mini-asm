import { prisma } from './prisma';
import { recoverInterruptedScans, startScan } from './scan-runner';

export const FREQUENCIES = ['DAILY', 'WEEKLY', 'MONTHLY'] as const;
export type Frequency = (typeof FREQUENCIES)[number];

const DAY_MS = 24 * 60 * 60 * 1000;
const INTERVAL_MS: Record<Frequency, number> = { DAILY: DAY_MS, WEEKLY: 7 * DAY_MS, MONTHLY: 30 * DAY_MS };
const TICK_MS = 60 * 1000;

export function nextRunAfter(frequency: string, from = new Date()): Date {
    return new Date(from.getTime() + (INTERVAL_MS[frequency as Frequency] ?? DAY_MS));
}

async function tick() {
    const due = await prisma.schedule.findMany({
        where: { active: true, nextRun: { lte: new Date() } },
        orderBy: { nextRun: 'asc' },
    });

    for (const schedule of due) {
        let started = false;
        try {
            await startScan(schedule.target, 'SCHEDULED');
            started = true;
        } catch (error) {
            // Typically the concurrency limit or a target that no longer resolves.
            console.error(`[scheduler] could not start scan for ${schedule.target}:`, error instanceof Error ? error.message : error);
        }
        // Always move the schedule on, so a failing target is retried next period instead of every minute.
        await prisma.schedule.update({
            where: { id: schedule.id },
            data: { nextRun: nextRunAfter(schedule.frequency), ...(started ? { lastRun: new Date() } : {}) },
        });
    }
}

const globalState = globalThis as unknown as { __asmScheduler?: NodeJS.Timeout };

/** Starts the in-process scheduler. Safe to call more than once. */
export async function startScheduler() {
    if (globalState.__asmScheduler) return;
    const run = () => tick().catch((error) => console.error('[scheduler] tick failed:', error));
    globalState.__asmScheduler = setInterval(run, TICK_MS);
    globalState.__asmScheduler.unref?.();

    await recoverInterruptedScans().catch((error) => console.error('[scan] recovery failed:', error));
    run();
}
