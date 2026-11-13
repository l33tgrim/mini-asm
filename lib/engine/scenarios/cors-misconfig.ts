import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

const EVIL_ORIGIN = 'https://payinc-cors-probe.example';

/**
 * CORS misconfiguration: reflect an arbitrary Origin and, worse, allow
 * credentials with it. Read-only GET carrying an Origin header.
 */
export const corsMisconfig: Scenario = {
    id: 'cors-misconfig',
    name: 'CORS Misconfiguration',
    description: 'Check whether web services reflect an arbitrary Origin, especially with credentials allowed.',
    category: 'VULN',
    maxSeverity: 'HIGH',
    attckTactic: 'Collection',
    attckTechnique: 'T1539 Steal Web Session Cookie',
    requiresActive: false,
    intrusive: true,
    tags: ['web', 'cors'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const webs = webTargetsFrom(await ensureServices(ctx));
        if (webs.length === 0) {
            results.push({ title: 'No web services to test for CORS', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' });
            return results;
        }
        for (const w of webs) {
            const probe = await httpGet(w.url, { headers: { Origin: EVIL_ORIGIN }, timeout: 6000 });
            const acao = probe.headers['access-control-allow-origin'];
            const acac = probe.headers['access-control-allow-credentials'];
            if (acao === EVIL_ORIGIN || acao === '*') {
                const withCreds = acac === 'true' && acao === EVIL_ORIGIN;
                results.push({
                    title: `${withCreds ? 'Credentialed ' : ''}CORS reflection on ${w.host}:${w.port}`,
                    severity: withCreds ? 'HIGH' : acao === '*' ? 'LOW' : 'MEDIUM',
                    outcome: 'VULNERABLE',
                    target: w.url,
                    attckTactic: 'Collection',
                    attckTechnique: 'T1539 Steal Web Session Cookie',
                    evidence: `Access-Control-Allow-Origin: ${acao}${acac ? `, Access-Control-Allow-Credentials: ${acac}` : ''}. ${withCreds ? 'An attacker origin can read authenticated responses.' : ''}`,
                    remediation: 'Allowlist specific trusted origins; never reflect arbitrary Origin with credentials enabled.',
                });
            }
        }
        if (results.length === 0) results.push({ title: 'No CORS reflection found', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'Arbitrary Origin was not reflected.' });
        return results;
    },
};
