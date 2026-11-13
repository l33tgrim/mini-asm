import { runScenario, type EngagementContext, type PlaybookStepInput, type ScenarioRunOutput } from './runner';
import { listScenarios } from './registry';
import type { ScenarioResult } from './types';
import type { ServiceRef } from './scenarios/_shared';
import { scoreResults, type RiskScore } from '@/lib/report/risk';
import { askClaude, hasClaudeKey, DEFAULT_MODEL } from '@/lib/ai/client';
import { classifyScope } from '@/lib/safety/scope';

const SENSITIVE_PORTS = new Set([6379, 9200, 2375, 11211, 27017, 3306, 5432, 5900, 10250, 3389]);
const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888]);

/**
 * Deterministic planner. Given what recon discovered, decide which scenarios to
 * run next. Active proofs are only planned when the engagement is authorized and
 * in ACTIVE mode; otherwise the plan stays safe.
 */
export function deterministicPlan(services: ServiceRef[], target: string, eng: EngagementContext): PlaybookStepInput[] {
    const plan: PlaybookStepInput[] = [];
    const add = (id: string) => { if (!plan.find((p) => p.scenarioId === id)) plan.push({ scenarioId: id }); };

    const hasWeb = services.some((s) => WEB_PORTS.has(s.port));
    const hasSensitive = services.some((s) => SENSITIVE_PORTS.has(s.port));
    const isDomain = classifyScope(target) === 'DOMAIN';
    const canActive = eng.mode === 'ACTIVE' && eng.authorized;

    // Always-safe posture and vuln checks.
    add('cve-enrichment');
    add('tls-posture');
    add('exposed-services');
    if (isDomain) { add('email-posture'); add('subdomain-takeover'); }

    if (hasWeb) {
        add('security-headers');
        add('cookie-security');
        add('cors-misconfig');
        add('http-methods');
        add('open-redirect');
        add('directory-listing');
        add('custom-http-checks');
        if (canActive) add('waf-detect-bypass');
    }

    // Active proofs only when sensitive surface exists and we are authorized.
    if (hasSensitive && canActive) {
        add('proof-of-reach');
        add('proof-of-command');
        add('proof-of-data');
    }
    return plan;
}

/**
 * Optional AI planner (Fable 5.2). Given the recon summary and the catalog, let
 * the model choose and order the follow-on scenarios. It can only ever pick
 * real scenario ids, and every pick still passes the safety gate at run time, so
 * the model widens nothing. Falls back to the deterministic plan.
 */
async function aiPlan(services: ServiceRef[], target: string, eng: EngagementContext, reconResults: ScenarioResult[]): Promise<{ plan: PlaybookStepInput[]; by: string }> {
    const fallback = deterministicPlan(services, target, eng);
    if (!hasClaudeKey()) return { plan: fallback, by: 'deterministic' };

    const catalog = listScenarios()
        .filter((s) => !s.requiresActive || (eng.mode === 'ACTIVE' && eng.authorized))
        .map((s) => `${s.id} [${s.category}] ${s.requiresActive ? '(active)' : '(safe)'}: ${s.description}`)
        .join('\n');
    const surface = services.map((s) => `${s.ip}:${s.port} ${s.service}${s.version ? ' ' + s.version : ''}`).join(', ') || 'no services found';
    const findings = reconResults.map((r) => `${r.severity} ${r.title}`).join('; ');

    const system = `You plan a NON-DESTRUCTIVE breach simulation. Choose which scenarios to run next against an AUTHORIZED target, given what recon found. Respond with ONLY a JSON array of scenario ids from the catalog, ordered, no prose. Pick only ids that are relevant to the discovered surface. You may only pick active scenarios if the catalog lists them as (active).`;
    const user = `Target: ${target} (mode=${eng.mode}, authorized=${eng.authorized})\nDiscovered surface: ${surface}\nRecon findings: ${findings}\n\nCatalog:\n${catalog}\n\nReturn the ordered JSON array of scenario ids to run.`;

    const res = await askClaude(system, user, 600);
    if (res.ok && res.text) {
        const m = res.text.match(/\[[\s\S]*\]/);
        if (m) {
            try {
                const ids = JSON.parse(m[0]) as string[];
                const valid = new Set(listScenarios().map((s) => s.id));
                const plan = ids.filter((id) => valid.has(id)).map((id) => ({ scenarioId: id }));
                if (plan.length) return { plan, by: `ai:${DEFAULT_MODEL}` };
            } catch { /* fall through */ }
        }
    }
    return { plan: fallback, by: 'deterministic (ai fallback)' };
}

async function narrate(target: string, risk: RiskScore, results: ScenarioResult[]): Promise<string> {
    const proven = results.filter((r) => r.outcome === 'PROVEN');
    const vuln = results.filter((r) => r.outcome === 'VULNERABLE');

    if (hasClaudeKey()) {
        const facts = [...proven, ...vuln].slice(0, 25).map((r) => `[${r.outcome} ${r.severity}] ${r.title}: ${r.evidence ?? ''}`).join('\n');
        const res = await askClaude(
            'You are a penetration tester writing a concise, factual attack narrative from non-destructive findings. 2-4 short paragraphs. No fabrication beyond the facts given.',
            `Target: ${target}. Posture score ${risk.score}/100 (grade ${risk.grade}).\nFindings:\n${facts}\n\nWrite the narrative: how an attacker would chain these, and the single most urgent fix.`,
            800
        );
        if (res.ok && res.text) return res.text.trim();
    }

    // Template fallback.
    const lines: string[] = [];
    lines.push(`Assessment of ${target} scored ${risk.score}/100 (grade ${risk.grade}): ${risk.headline}.`);
    if (proven.length) lines.push(`Proven, non-destructively: ${proven.map((p) => p.title).join('; ')}.`);
    if (vuln.length) lines.push(`Confirmed weaknesses: ${vuln.slice(0, 8).map((v) => v.title).join('; ')}${vuln.length > 8 ? ', and more' : ''}.`);
    const worst = [...proven, ...vuln].sort((a, b) => ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(b.severity) - ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(a.severity))[0];
    if (worst?.remediation) lines.push(`Most urgent fix: ${worst.remediation}`);
    return lines.join('\n\n');
}

export interface AutopilotResult {
    target: string;
    mode: string;
    plannedBy: string;
    runs: ScenarioRunOutput[];
    risk: RiskScore;
    narrative: string;
}

/**
 * Autonomous assessment: recon first, then an adaptive plan of follow-on
 * scenarios chosen from what was discovered, then scoring and a narrative.
 * Every scenario still passes the safety gate, so autonomy never widens scope.
 */
export async function runAutopilot(target: string, eng: EngagementContext): Promise<AutopilotResult> {
    const shared: Record<string, unknown> = {};
    const runs: ScenarioRunOutput[] = [];

    const recon = await runScenario('recon-exposure', target, eng, shared);
    runs.push(recon);

    const services = (shared.services as ServiceRef[] | undefined) || [];
    const { plan, by } = await aiPlan(services, target, eng, recon.results);

    for (const step of plan) {
        runs.push(await runScenario(step.scenarioId, target, eng, shared, step.params || {}));
    }

    const allResults = runs.flatMap((r) => r.results);
    const risk = scoreResults(allResults);
    const narrative = await narrate(target, risk, allResults);

    return { target, mode: eng.mode, plannedBy: by, runs, risk, narrative };
}
