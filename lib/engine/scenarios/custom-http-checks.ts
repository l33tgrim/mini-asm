import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices, webTargetsFrom, paramJson } from './_shared';
import { httpGet } from '../primitives';

interface Check {
    path: string;
    title?: string;
    severity?: Severity;
    signature?: string; // regex tested against the response body
    status?: number; // expected status (defaults to 200 when no signature)
}

// A sensible default set covering several different issue classes. Override the
// `checks` param to test anything you like, which is what makes this modular.
const DEFAULT_CHECKS: Check[] = [
    { path: '/admin', title: 'Admin panel reachable', severity: 'MEDIUM', status: 200 },
    { path: '/.env', title: 'Environment file exposed', severity: 'CRITICAL', signature: '^[A-Z0-9_]+\\s*=' },
    { path: '/backup.zip', title: 'Backup archive exposed', severity: 'HIGH', status: 200 },
    { path: '/phpinfo.php', title: 'phpinfo() exposed', severity: 'HIGH', signature: 'phpinfo\\(\\)' },
    { path: '/.git/config', title: '.git config exposed', severity: 'HIGH', signature: '\\[core\\]' },
    { path: '/swagger.json', title: 'API schema exposed', severity: 'LOW', signature: 'swagger|openapi' },
    { path: '/actuator/health', title: 'Spring actuator exposed', severity: 'MEDIUM', signature: '"status"' },
];

/**
 * Modular, parameterized web probe. Each "check" is a path plus an optional
 * signature and/or expected status. This single scenario can test many
 * different issues purely from configuration, so a custom playbook can point it
 * at whatever matters for a given threat. All probes are read-only GETs and the
 * response body is redacted in the evidence.
 */
export const customHttpChecks: Scenario = {
    id: 'custom-http-checks',
    name: 'Custom Web Checks (parameterized)',
    description: 'Run a configurable list of read-only path checks against web services. Supply `checks` to test any issue.',
    category: 'EXPOSURE',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1595.003 Wordlist Scanning',
    requiresActive: false,
    intrusive: true,
    tags: ['web', 'modular', 'custom'],
    params: [
        {
            key: 'checks',
            label: 'Checks (JSON array)',
            type: 'json',
            required: false,
            help: 'Array of { path, title?, severity?, signature? (regex), status? }. Defaults to a built-in set.',
        },
    ],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const checks = paramJson<Check[]>(ctx, 'checks', DEFAULT_CHECKS);
        const services = await ensureServices(ctx);
        const webs = webTargetsFrom(services);

        if (webs.length === 0) {
            results.push({ title: 'No web services to check', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' });
            return results;
        }

        for (const w of webs) {
            for (const c of checks) {
                if (!c.path) continue;
                const probe = await httpGet(w.url + c.path, { timeout: 5000, maxBody: 2048 });
                if (probe.status === 0) continue;

                let matched = false;
                if (c.signature) {
                    try {
                        matched = new RegExp(c.signature, 'im').test(probe.bodySnippet) && probe.status < 400;
                    } catch {
                        matched = false; // bad regex supplied, treat as no match
                    }
                } else {
                    matched = probe.status === (c.status ?? 200);
                }

                if (matched) {
                    results.push({
                        title: `${c.title || 'Check matched'}: ${c.path} on ${w.host}:${w.port}`,
                        severity: c.severity || 'MEDIUM',
                        outcome: 'VULNERABLE',
                        target: w.url + c.path,
                        attckTactic: 'Initial Access',
                        attckTechnique: 'T1595.003 Wordlist Scanning',
                        evidence: `HTTP ${probe.status} at ${c.path}${c.signature ? ` matched signature /${c.signature}/` : ''} (body redacted).`,
                        remediation: `Confirm ${c.path} should be reachable. Block or protect it if not.`,
                    });
                }
            }
        }

        if (results.length === 0) {
            results.push({ title: 'No custom web checks matched', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: `Ran ${checks.length} check(s) against ${webs.length} web target(s); nothing matched.` });
        }
        return results;
    },
};
