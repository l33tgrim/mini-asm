import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet, type HttpProbe } from '../primitives';

export interface TechHit {
    product: string;
    version: string;
}

function ver(v: string): number[] {
    return v.split('.').map((n) => parseInt(n, 10) || 0);
}

export function olderThan(v: string, target: string): boolean {
    const a = ver(v);
    const b = ver(target);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const x = a[i] ?? 0;
        const y = b[i] ?? 0;
        if (x !== y) return x < y;
    }
    return false;
}

/** Work out which products and versions a response gives away. */
export function fingerprint(headers: Record<string, string>, body: string): TechHit[] {
    const hits: TechHit[] = [];
    const add = (product: string, version?: string) => {
        if (version && !hits.some((h) => h.product === product)) hits.push({ product, version });
    };
    const server = headers['server'] || '';
    const powered = headers['x-powered-by'] || '';

    add('Apache httpd', server.match(/Apache\/(\d+\.\d+\.\d+)/i)?.[1]);
    add('nginx', server.match(/nginx\/(\d+\.\d+\.\d+)/i)?.[1]);
    add('Microsoft IIS', server.match(/Microsoft-IIS\/(\d+\.\d+)/i)?.[1]);
    add('OpenSSL', server.match(/OpenSSL\/(\d+\.\d+\.\d+)/i)?.[1]);
    add('Apache Tomcat', (server.match(/(?:Apache-Coyote|Tomcat)\/(\d+\.\d+(?:\.\d+)?)/i) || body.match(/Apache Tomcat\/(\d+\.\d+\.\d+)/))?.[1]);
    add('PHP', (powered.match(/PHP\/(\d+\.\d+\.\d+)/i) || server.match(/PHP\/(\d+\.\d+\.\d+)/i))?.[1]);
    add('ASP.NET', headers['x-aspnet-version']?.match(/(\d+\.\d+)/)?.[1]);
    add('WordPress', body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress (\d+\.\d+(?:\.\d+)?)/i)?.[1]);
    add('Drupal', (headers['x-generator'] || '').match(/Drupal (\d+)/i)?.[1] || body.match(/content=["']Drupal (\d+)/i)?.[1]);
    add('jQuery', body.match(/jquery[-/](\d+\.\d+\.\d+)(?:\.min)?\.js/i)?.[1]);
    add('Bootstrap', body.match(/bootstrap[-/@](\d+\.\d+\.\d+)/i)?.[1]);
    add('AngularJS', body.match(/angular(?:js)?[-/](1\.\d+\.\d+)/i)?.[1]);
    return hits;
}

interface VulnRule {
    product: string;
    below: string;
    severity: Severity;
    reference: string;
    summary: string;
    remediation: string;
}

// Small, high-confidence list. Each rule is "anything older than X is known
// vulnerable or no longer receives security fixes".
export const TECH_RULES: VulnRule[] = [
    { product: 'Apache httpd', below: '2.4.51', severity: 'CRITICAL', reference: 'CVE-2021-41773 / CVE-2021-42013', summary: 'Versions before 2.4.51 include releases with a path traversal flaw that is in the CISA Known Exploited list.', remediation: 'Upgrade Apache httpd to the current 2.4 release.' },
    { product: 'nginx', below: '1.21.0', severity: 'HIGH', reference: 'CVE-2021-23017', summary: 'Resolver memory flaw fixed in 1.21.0 (and 1.20.1).', remediation: 'Upgrade nginx to the current stable release.' },
    { product: 'Microsoft IIS', below: '10.0', severity: 'HIGH', reference: 'End of support', summary: 'IIS before 10.0 ships with Windows Server versions that no longer receive security updates.', remediation: 'Move the site to a supported Windows Server release.' },
    { product: 'OpenSSL', below: '3.0.0', severity: 'HIGH', reference: 'End of support', summary: 'OpenSSL 1.x no longer receives public security fixes.', remediation: 'Upgrade to a supported OpenSSL 3.x release.' },
    { product: 'Apache Tomcat', below: '9.0.0', severity: 'HIGH', reference: 'End of support', summary: 'Tomcat 8.5 and older are end of life.', remediation: 'Upgrade to a supported Tomcat release.' },
    { product: 'PHP', below: '8.2.0', severity: 'HIGH', reference: 'End of support', summary: 'PHP branches before 8.2 no longer receive security fixes.', remediation: 'Upgrade to a supported PHP branch.' },
    { product: 'Drupal', below: '10', severity: 'HIGH', reference: 'End of support', summary: 'Drupal 9 and older are end of life.', remediation: 'Upgrade to a supported Drupal major version.' },
    { product: 'jQuery', below: '3.5.0', severity: 'MEDIUM', reference: 'CVE-2020-11022 / CVE-2020-11023', summary: 'Cross-site scripting flaws in HTML handling, fixed in 3.5.0.', remediation: 'Upgrade jQuery to the current 3.x release.' },
    { product: 'Bootstrap', below: '3.4.1', severity: 'LOW', reference: 'CVE-2019-8331', summary: 'Cross-site scripting in tooltip and popover data attributes, fixed in 3.4.1.', remediation: 'Upgrade Bootstrap.' },
    { product: 'AngularJS', below: '2.0.0', severity: 'MEDIUM', reference: 'End of support', summary: 'AngularJS 1.x has been end of life since January 2022 and has unpatched issues.', remediation: 'Plan a migration off AngularJS.' },
];

export function assess(hits: TechHit[]): { hit: TechHit; rule: VulnRule }[] {
    const out: { hit: TechHit; rule: VulnRule }[] = [];
    for (const hit of hits) {
        for (const rule of TECH_RULES) {
            if (rule.product === hit.product && olderThan(hit.version, rule.below)) out.push({ hit, rule });
        }
    }
    return out;
}

/**
 * Web technology and known-vulnerability check. Reads the home page once per
 * web target, works out product versions from headers and markup, and matches
 * them against known vulnerable or unsupported releases. Detection is by
 * version only; nothing is sent that tries to trigger a flaw.
 */
export const webTechVulns: Scenario = {
    id: 'web-tech-vulns',
    name: 'Web Technology and Known Vulnerabilities',
    description: 'Fingerprint web servers, frameworks and front-end libraries from one normal page request and flag versions with known vulnerabilities or no vendor support. Version matching only, no exploitation.',
    category: 'VULN',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Reconnaissance',
    attckTechnique: 'T1592.002 Gather Victim Host Information: Software',
    requiresActive: false,
    intrusive: false,
    tags: ['web', 'vuln', 'cve', 'fingerprint'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const webs = webTargetsFrom(await ensureServices(ctx));
        if (webs.length === 0) {
            return [{ title: 'No web services to check', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' }];
        }

        for (const w of webs) {
            let probe: HttpProbe = await httpGet(`${w.url}/`, { timeout: 6000, maxBody: 65536 });
            // Follow one same-host redirect so the real page is read.
            const next = probe.headers['location'];
            if (probe.status >= 300 && probe.status < 400 && next) {
                try {
                    const url = new URL(next, `${w.url}/`);
                    if (url.hostname === w.host) probe = await httpGet(url.toString(), { timeout: 6000, maxBody: 65536 });
                } catch {
                    // keep the first response
                }
            }
            if (probe.status === 0) continue;

            const hits = fingerprint(probe.headers, probe.bodySnippet);
            const findings = assess(hits);
            for (const { hit, rule } of findings) {
                results.push({
                    title: `${hit.product} ${hit.version} on ${w.host}:${w.port} (${rule.reference})`,
                    severity: rule.severity,
                    outcome: 'VULNERABLE',
                    target: w.url,
                    attckTactic: 'Reconnaissance',
                    attckTechnique: 'T1592.002 Gather Victim Host Information: Software',
                    evidence: `The site reports ${hit.product} ${hit.version}. ${rule.summary} Matched on the reported version only, so confirm the patch level on the host (some distributions backport fixes).`,
                    remediation: rule.remediation,
                });
            }
            if (hits.length) {
                results.push({
                    title: `Software versions disclosed by ${w.host}:${w.port}`,
                    severity: 'LOW',
                    outcome: 'INFO',
                    target: w.url,
                    evidence: `Visible to any visitor: ${hits.map((h) => `${h.product} ${h.version}`).join(', ')}.`,
                    remediation: 'Hide version numbers in server banners and headers. It will not fix a flaw, but it stops easy targeting.',
                });
            }
        }

        if (!results.some((r) => r.outcome === 'VULNERABLE')) {
            results.unshift({ title: 'No known-vulnerable web software versions found', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: `Checked ${webs.length} web target(s). Software that hides its version cannot be assessed this way.` });
        }
        return results;
    },
};
