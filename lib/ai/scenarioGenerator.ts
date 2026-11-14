import type { ScenarioCategory, Severity } from '@/lib/engine/types';
import { askClaude, hasClaudeKey, DEFAULT_MODEL } from './client';

export interface ScenarioSpec {
    id: string;
    name: string;
    description: string;
    category: ScenarioCategory;
    maxSeverity: Severity;
    attckTactic: string;
    attckTechnique: string;
    requiresActive: boolean;
    intrusive: boolean;
    tags: string[];
    steps: string[];
}

const SYSTEM = `You design scenarios for a NON-DESTRUCTIVE breach & attack simulation tool used for AUTHORIZED testing only.
Hard rules for every scenario you propose:
- It must be non-destructive: no writes, no deletes, no denial of service, no data exfiltration.
- Proofs may only: confirm reachability, run a read-only command, or read metadata (counts, names). Never copy records.
- It may only use safe primitives: tcpConnect, grabBanner, httpGet (read-only), redisReadOnly (read-only commands).
- Anything that sends attack-shaped traffic or interacts beyond passive recon must set requiresActive=true.
Respond with ONLY a JSON object matching this TypeScript type, no prose:
{ "id": string (kebab-case), "name": string, "description": string,
  "category": "RECON"|"EXPOSURE"|"VULN"|"WAF"|"PROOF"|"POSTURE",
  "maxSeverity": "INFO"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
  "attckTactic": string, "attckTechnique": string (e.g. "T1190 Exploit Public-Facing Application"),
  "requiresActive": boolean, "intrusive": boolean, "tags": string[],
  "steps": string[] (each step a plain-English safe action using the allowed primitives) }`;

function localTemplate(request: string): ScenarioSpec {
    const id = request.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'new-scenario';
    return {
        id,
        name: request.slice(0, 60) || 'New Scenario',
        description: `Scenario drafted from request: ${request}`,
        category: 'EXPOSURE',
        maxSeverity: 'MEDIUM',
        attckTactic: 'Initial Access',
        attckTechnique: 'T1190 Exploit Public-Facing Application',
        requiresActive: true,
        intrusive: true,
        tags: ['draft'],
        steps: [
            'Resolve the target and reuse shared recon via ensureServices(ctx).',
            'TODO: describe the non-destructive check using safe primitives.',
            'Return results with outcome SECURE / VULNERABLE / PROVEN and a remediation.',
        ],
    };
}

/**
 * Draft a scenario spec from a natural-language threat description. Uses Claude
 * (Fable 5.2) when ANTHROPIC_API_KEY is set, otherwise returns a local template
 * for the agent or a human to complete. A generated spec is a PROPOSAL; the
 * run() logic is written and reviewed by a human/agent before it executes.
 */
export async function generateScenarioSpec(request: string): Promise<{ spec: ScenarioSpec; source: string; model: string }> {
    if (hasClaudeKey()) {
        const res = await askClaude(SYSTEM, `Design a scenario for this authorized test request:\n\n${request}`);
        if (res.ok && res.text) {
            const jsonMatch = res.text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                try {
                    const spec = JSON.parse(jsonMatch[0]) as ScenarioSpec;
                    return { spec, source: 'claude', model: DEFAULT_MODEL };
                } catch {
                    /* fall through to template */
                }
            }
        }
    }
    return { spec: localTemplate(request), source: 'template', model: 'none' };
}

/**
 * Render a ready-to-edit TypeScript scenario file from a spec. The generated
 * run() is a stub that does nothing until a human/agent implements it, so a
 * dropped-in file can never execute un-reviewed attack logic.
 */
export function scaffoldScenarioFile(spec: ScenarioSpec): string {
    const constName = spec.id.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const steps = spec.steps.map((s) => `     *   - ${s.replace(/\*\//g, '* /')}`).join('\n');
    return `import type { Scenario, ScenarioResult } from '../types';
import { ensureServices } from './_shared';

/**
 * ${spec.name}
 * ${spec.description}
 *
 * Proposed steps (implement safely, non-destructively):
${steps}
 */
export const ${constName}: Scenario = {
    id: '${spec.id}',
    name: ${JSON.stringify(spec.name)},
    description: ${JSON.stringify(spec.description)},
    category: '${spec.category}',
    maxSeverity: '${spec.maxSeverity}',
    attckTactic: ${JSON.stringify(spec.attckTactic)},
    attckTechnique: ${JSON.stringify(spec.attckTechnique)},
    requiresActive: ${spec.requiresActive},
    intrusive: ${spec.intrusive},
    tags: ${JSON.stringify(spec.tags)},
    async run(ctx) {
        const results: ScenarioResult[] = [];
        await ensureServices(ctx);
        // TODO: implement this scenario using only safe primitives
        // (tcpConnect, grabBanner, httpGet, redisReadOnly). Non-destructive only.
        results.push({
            title: ${JSON.stringify(spec.name + ' (not yet implemented)')},
            severity: 'INFO',
            outcome: 'INFO',
            target: ctx.target,
            evidence: 'Scaffolded scenario. Implement run() before using in an engagement.',
        });
        return results;
    },
};
`;
}
