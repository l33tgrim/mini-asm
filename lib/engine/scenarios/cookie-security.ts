import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

/**
 * Session cookie hardening: Secure, HttpOnly, SameSite flags.
 */
export const cookieSecurity: Scenario = {
    id: 'cookie-security',
    name: 'Cookie Security Flags',
    description: 'Inspect Set-Cookie headers for missing Secure / HttpOnly / SameSite attributes.',
    category: 'POSTURE',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Credential Access',
    attckTechnique: 'T1539 Steal Web Session Cookie',
    requiresActive: false,
    intrusive: false,
    tags: ['web', 'cookies'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const webs = webTargetsFrom(await ensureServices(ctx));
        for (const w of webs) {
            const probe = await httpGet(w.url, { timeout: 6000 });
            const setCookie = probe.headers['set-cookie'];
            if (!setCookie) continue;
            const issues: string[] = [];
            if (!/;\s*secure/i.test(setCookie)) issues.push('missing Secure');
            if (!/;\s*httponly/i.test(setCookie)) issues.push('missing HttpOnly');
            if (!/;\s*samesite/i.test(setCookie)) issues.push('missing SameSite');
            if (issues.length) {
                results.push({
                    title: `Weak cookie attributes on ${w.host}:${w.port}`,
                    severity: issues.includes('missing HttpOnly') ? 'MEDIUM' : 'LOW',
                    outcome: 'VULNERABLE',
                    target: w.url,
                    attckTactic: 'Credential Access',
                    attckTechnique: 'T1539 Steal Web Session Cookie',
                    evidence: `Set-Cookie ${issues.join(', ')} (cookie values redacted).`,
                    remediation: 'Set Secure, HttpOnly and SameSite on session cookies.',
                });
            }
        }
        if (results.length === 0) results.push({ title: 'No weak cookies observed', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No Set-Cookie issues found on the reachable responses.' });
        return results;
    },
};
