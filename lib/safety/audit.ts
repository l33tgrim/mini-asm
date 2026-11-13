import { prisma } from '@/lib/prisma';

export interface AuditEntry {
    engagementId?: string | null;
    action: string;
    target?: string | null;
    detail?: string | null;
    actor?: string;
}

/**
 * Append-only audit trail. Every gate decision (allow or deny) and every active
 * action is recorded. Writes to the AuditLog table; failures are logged but
 * never swallow the caller, because losing an audit record must be visible.
 */
export async function audit(entry: AuditEntry): Promise<void> {
    const line = `[AUDIT] ${entry.action} target=${entry.target ?? '-'} actor=${entry.actor ?? 'system'} :: ${entry.detail ?? ''}`;
    console.log(line);
    try {
        await prisma.auditLog.create({
            data: {
                engagementId: entry.engagementId ?? null,
                action: entry.action,
                target: entry.target ?? null,
                detail: entry.detail ?? null,
                actor: entry.actor ?? 'system',
            },
        });
    } catch (e) {
        console.error('[AUDIT] FAILED TO PERSIST AUDIT RECORD:', e);
    }
}
