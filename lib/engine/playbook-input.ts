import { getScenario } from './registry';
import { TargetError } from '@/lib/targets';

const MAX_STEPS = 50;
const MAX_PARAMS_BYTES = 8 * 1024;

export interface PlaybookFields {
    name?: string;
    description?: string | null;
    threat?: string | null;
    attckTactics?: string | null;
    steps?: { scenarioId: string; order: number; params: string | null }[];
}

const text = (value: unknown, max: number) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

/**
 * Validates a custom playbook payload. Every step must name a real scenario, so
 * a stored playbook can never reference something the engine does not ship.
 * Throws TargetError (reported as a 400) on bad input.
 */
export function parsePlaybookInput(body: Record<string, unknown>, requireName: boolean): PlaybookFields {
    const out: PlaybookFields = {};

    if (body.name !== undefined || requireName) {
        const name = text(body.name, 120);
        if (!name) throw new TargetError('A name is required.');
        out.name = name;
    }
    if (body.description !== undefined) out.description = text(body.description, 1000) || null;
    if (body.threat !== undefined) out.threat = text(body.threat, 200) || null;
    if (body.attckTactics !== undefined) {
        const tactics = Array.isArray(body.attckTactics) ? body.attckTactics.map(String).join(',') : text(body.attckTactics, 500);
        out.attckTactics = tactics.slice(0, 500) || null;
    }

    if (body.steps !== undefined) {
        if (!Array.isArray(body.steps) || body.steps.length === 0 || body.steps.length > MAX_STEPS) {
            throw new TargetError(`A playbook needs between 1 and ${MAX_STEPS} steps.`);
        }
        out.steps = body.steps.map((step, i) => {
            const s = (step ?? {}) as Record<string, unknown>;
            if (typeof s.scenarioId !== 'string' || !getScenario(s.scenarioId)) {
                throw new TargetError(`Step ${i + 1} does not name a known scenario.`);
            }
            let params: string | null = null;
            if (s.params !== undefined && s.params !== null) {
                if (typeof s.params !== 'object' || Array.isArray(s.params)) throw new TargetError(`Step ${i + 1}: params must be a JSON object.`);
                params = JSON.stringify(s.params);
                if (params.length > MAX_PARAMS_BYTES) throw new TargetError(`Step ${i + 1}: params are too large.`);
            }
            return { scenarioId: s.scenarioId, order: i, params };
        });
    } else if (requireName) {
        throw new TargetError('A playbook needs at least one step.');
    }

    return out;
}
