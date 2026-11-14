import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom, paramList } from './_shared';
import { httpGet } from '../primitives';

const CANARY = 'https://payinc-redirect-probe.example/';
const DEFAULT_PARAMS = ['url', 'next', 'redirect', 'return', 'returnUrl', 'dest', 'destination', 'continue'];

/**
 * Open redirect: a redirect parameter that sends users to an external URL.
 * Parameterized: override `redirectParams` to test your own parameter names.
 */
export const openRedirect: Scenario = {
    id: 'open-redirect',
    name: 'Open Redirect',
    description: 'Test common redirect parameters for external redirection to an attacker URL.',
    category: 'VULN',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1566 Phishing',
    requiresActive: false,
    intrusive: true,
    tags: ['web', 'redirect'],
    params: [{ key: 'redirectParams', label: 'Redirect params', type: 'stringlist', help: 'Parameter names to test (default: url,next,redirect,...)' }],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const paramNames = paramList(ctx, 'redirectParams', DEFAULT_PARAMS);
        const webs = webTargetsFrom(await ensureServices(ctx));
        for (const w of webs) {
            for (const p of paramNames) {
                const probe = await httpGet(`${w.url}/?${p}=${encodeURIComponent(CANARY)}`, { timeout: 5000 });
                const loc = probe.headers['location'];
                if (loc && (loc.startsWith(CANARY) || loc.includes('payinc-redirect-probe.example'))) {
                    results.push({
                        title: `Open redirect via "${p}" on ${w.host}:${w.port}`,
                        severity: 'MEDIUM',
                        outcome: 'VULNERABLE',
                        target: `${w.url}/?${p}=`,
                        attckTactic: 'Initial Access',
                        attckTechnique: 'T1566 Phishing',
                        evidence: `HTTP ${probe.status} redirected to the external canary via Location: ${loc}`,
                        remediation: `Validate redirect targets against an allowlist; do not redirect to arbitrary external URLs via "${p}".`,
                    });
                }
            }
        }
        if (results.length === 0) results.push({ title: 'No open redirect found', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'Tested redirect params did not redirect externally.' });
        return results;
    },
};
