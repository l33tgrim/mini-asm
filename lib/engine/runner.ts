import type { Scenario, ScenarioResult, Mode, RunContext } from './types';
import { getScenario, getPlaybook } from './registry';
import { ScopeItem, isTargetInScope, assertActiveAllowed } from '@/lib/safety/scope';
import { assertNotKilled } from '@/lib/safety/killswitch';
import { audit } from '@/lib/safety/audit';

export interface EngagementContext {
    engagementId?: string;
    mode: Mode;
    scope: ScopeItem[];
    actor: string;
    /** True only once an operator has formally authorized the engagement. */
    authorized: boolean;
}

export interface GateDecision {
    allowed: boolean;
    reason: string;
}

/**
 * The single choke point every scenario execution passes through. No scenario
 * runs unless this says yes.
 */
export function evaluateGate(scenario: Scenario, target: string, eng: EngagementContext): GateDecision {
    // 1. Kill switch.
    try {
        assertNotKilled();
    } catch (e) {
        return { allowed: false, reason: (e as Error).message };
    }

    // 2. Target must be in scope, always (recon included).
    const inScope = isTargetInScope(target, eng.scope);
    if (!inScope.inScope) {
        return { allowed: false, reason: `OUT_OF_SCOPE: ${inScope.reason}` };
    }

    // 3. Active / intrusive scenarios need an AUTHORIZED engagement, ACTIVE
    //    mode, AND an ownership-verified target. SAFE scenarios (recon, posture,
    //    vuln detection) run on any in-scope target.
    if (scenario.requiresActive) {
        if (!eng.authorized) {
            return { allowed: false, reason: `NOT_AUTHORIZED: engagement must be authorized before scenario "${scenario.id}" can run` };
        }
        if (eng.mode !== 'ACTIVE') {
            return { allowed: false, reason: `scenario "${scenario.id}" requires ACTIVE mode (engagement is ${eng.mode})` };
        }
        const active = assertActiveAllowed(target, eng.scope);
        if (!active.allowed) {
            return { allowed: false, reason: `NOT_VERIFIED: ${active.reason}` };
        }
    }

    return { allowed: true, reason: inScope.reason };
}

export interface ScenarioRunOutput {
    scenarioId: string;
    scenarioName: string;
    target: string;
    status: 'COMPLETED' | 'BLOCKED' | 'FAILED';
    gate: GateDecision;
    results: ScenarioResult[];
    summary: string;
}

export async function runScenario(
    scenarioId: string,
    target: string,
    eng: EngagementContext,
    sharedState: Record<string, unknown> = {}
): Promise<ScenarioRunOutput> {
    const scenario = getScenario(scenarioId);
    if (!scenario) {
        return {
            scenarioId,
            scenarioName: scenarioId,
            target,
            status: 'FAILED',
            gate: { allowed: false, reason: 'unknown scenario' },
            results: [],
            summary: `Unknown scenario "${scenarioId}"`,
        };
    }

    const gate = evaluateGate(scenario, target, eng);

    await audit({
        engagementId: eng.engagementId,
        action: gate.allowed ? 'SCENARIO_ALLOWED' : 'SCENARIO_BLOCKED',
        target,
        actor: eng.actor,
        detail: `${scenario.id} (${scenario.category}, active=${scenario.requiresActive}, mode=${eng.mode}) :: ${gate.reason}`,
    });

    if (!gate.allowed) {
        return {
            scenarioId: scenario.id,
            scenarioName: scenario.name,
            target,
            status: 'BLOCKED',
            gate,
            results: [],
            summary: `BLOCKED: ${gate.reason}`,
        };
    }

    const logs: string[] = [];
    const ctx: RunContext = {
        target,
        mode: eng.mode,
        engagementId: eng.engagementId,
        state: sharedState,
        log: (m) => logs.push(m),
    };

    try {
        const results = await scenario.run(ctx);
        const proven = results.filter((r) => r.outcome === 'PROVEN').length;
        const vuln = results.filter((r) => r.outcome === 'VULNERABLE').length;
        await audit({
            engagementId: eng.engagementId,
            action: 'SCENARIO_COMPLETED',
            target,
            actor: eng.actor,
            detail: `${scenario.id}: ${results.length} results (${vuln} vulnerable, ${proven} proven)`,
        });
        return {
            scenarioId: scenario.id,
            scenarioName: scenario.name,
            target,
            status: 'COMPLETED',
            gate,
            results,
            summary: `${results.length} results, ${vuln} vulnerable, ${proven} proven`,
        };
    } catch (e) {
        await audit({
            engagementId: eng.engagementId,
            action: 'SCENARIO_FAILED',
            target,
            actor: eng.actor,
            detail: `${scenario.id}: ${(e as Error).message}`,
        });
        return {
            scenarioId: scenario.id,
            scenarioName: scenario.name,
            target,
            status: 'FAILED',
            gate,
            results: [
                {
                    title: `Scenario error: ${scenario.name}`,
                    severity: 'INFO',
                    outcome: 'ERROR',
                    target,
                    evidence: (e as Error).message,
                },
            ],
            summary: `FAILED: ${(e as Error).message}`,
        };
    }
}

/** Run every scenario in a playbook in order, sharing recon state between them. */
export async function runPlaybook(
    playbookId: string,
    target: string,
    eng: EngagementContext
): Promise<{ playbookId: string; playbookName: string; runs: ScenarioRunOutput[] }> {
    const pb = getPlaybook(playbookId);
    if (!pb) throw new Error(`Unknown playbook "${playbookId}"`);
    const shared: Record<string, unknown> = {};
    const runs: ScenarioRunOutput[] = [];
    for (const sid of pb.scenarioIds) {
        runs.push(await runScenario(sid, target, eng, shared));
    }
    return { playbookId: pb.id, playbookName: pb.name, runs };
}
