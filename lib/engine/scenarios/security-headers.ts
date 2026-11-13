import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

const HEADER_CHECKS: { header: string; severity: Severity; why: string }[] = [
    { header: 'strict-transport-security', severity: 'MEDIUM', why: 'no HSTS: connection can be downgraded to HTTP' },
    { header: 'content-security-policy', severity: 'MEDIUM', why: 'no CSP: weaker defence against XSS/injection' },
    { header: 'x-frame-options', severity: 'LOW', why: 'no X-Frame-Options: clickjacking risk (unless CSP frame-ancestors is set)' },
    { header: 'x-content-type-options', severity: 'LOW', why: 'no X-Content-Type-Options: MIME sniffing risk' },
    { header: 'referrer-policy', severity: 'LOW', why: 'no Referrer-Policy: referrer leakage' },
];

export const securityHeaders: Scenario = {
    id: 'security-headers',
    name: 'HTTP Security Headers',
    description: 'Grade web responses for missing security headers (HSTS, CSP, X-Frame-Options, etc).',
    category: 'POSTURE',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1189 Drive-by Compromise',
    requiresActive: false,
    intrusive: false,
    tags: ['web', 'headers', 'hardening'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        const webs = webTargetsFrom(services);

        if (webs.length === 0) {
            results.push({ title: 'No web services to grade', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' });
            return results;
        }

        for (const w of webs) {
            const probe = await httpGet(w.url, { timeout: 6000 });
            if (probe.status === 0) continue;
            const missing = HEADER_CHECKS.filter((c) => !probe.headers[c.header]);
            if (missing.length === 0) {
                results.push({ title: `Strong headers on ${w.host}:${w.port}`, severity: 'INFO', outcome: 'SECURE', target: w.url, evidence: 'All checked security headers are present.' });
                continue;
            }
            const worst = missing.reduce<Severity>((acc, c) => (['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(c.severity) > ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(acc) ? c.severity : acc), 'INFO');
            results.push({
                title: `${missing.length} missing security header(s) on ${w.host}:${w.port}`,
                severity: worst,
                outcome: 'VULNERABLE',
                target: w.url,
                attckTactic: 'Initial Access',
                attckTechnique: 'T1189 Drive-by Compromise',
                evidence: missing.map((m) => `Missing ${m.header}: ${m.why}`).join('\n'),
                remediation: 'Add the missing headers at the app or reverse proxy. Prioritise HSTS and CSP.',
            });
        }
        return results;
    },
};
