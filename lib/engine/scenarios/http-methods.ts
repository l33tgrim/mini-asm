import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

const RISKY = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];

/**
 * Dangerous HTTP methods: an OPTIONS request reveals the allowed verbs; risky
 * ones (PUT/DELETE/TRACE) widen the attack surface. OPTIONS is read-only.
 */
export const httpMethods: Scenario = {
    id: 'http-methods',
    name: 'HTTP Methods',
    description: 'Enumerate allowed HTTP methods and flag risky ones (PUT, DELETE, TRACE).',
    category: 'POSTURE',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1190 Exploit Public-Facing Application',
    requiresActive: false,
    intrusive: false,
    tags: ['web', 'methods'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const webs = webTargetsFrom(await ensureServices(ctx));
        for (const w of webs) {
            const probe = await httpGet(w.url, { method: 'OPTIONS', timeout: 5000 });
            const allow = probe.headers['allow'] || probe.headers['access-control-allow-methods'];
            if (!allow) continue;
            const risky = RISKY.filter((m) => allow.toUpperCase().includes(m));
            if (risky.length) {
                results.push({
                    title: `Risky HTTP methods on ${w.host}:${w.port}`,
                    severity: risky.includes('PUT') || risky.includes('DELETE') ? 'MEDIUM' : 'LOW',
                    outcome: 'VULNERABLE',
                    target: w.url,
                    attckTactic: 'Initial Access',
                    attckTechnique: 'T1190 Exploit Public-Facing Application',
                    evidence: `Server advertises methods: ${allow}. Risky: ${risky.join(', ')}.`,
                    remediation: 'Disable unused methods, especially PUT/DELETE/TRACE, at the server or proxy.',
                });
            }
        }
        if (results.length === 0) results.push({ title: 'No risky HTTP methods advertised', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'OPTIONS did not reveal risky methods.' });
        return results;
    },
};
