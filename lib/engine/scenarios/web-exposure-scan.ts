import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

interface ExposureCheck {
    path: string;
    title: string;
    severity: Severity;
    /** Must match the response body, so a generic 200 page never counts. */
    signature: RegExp;
    /** What the evidence may say about the content. Never the content itself. */
    summarise?: (body: string) => string;
    remediation: string;
}

const count = (body: string, re: RegExp) => (body.match(re) || []).length;

export const EXPOSURE_CHECKS: ExposureCheck[] = [
    {
        path: '/.git/HEAD', title: 'Source repository exposed', severity: 'HIGH',
        signature: /^(ref: refs\/heads\/\S+|[0-9a-f]{40})\s*$/m,
        summarise: () => 'The file has the format of a Git HEAD pointer, so the repository metadata is being served.',
        remediation: 'Block access to /.git on the web server and deploy from a build artefact instead of a working copy.',
    },
    {
        path: '/.env', title: 'Environment file exposed', severity: 'CRITICAL',
        signature: /^[A-Z][A-Z0-9_]{2,}\s*=/m,
        summarise: (b) => `${count(b, /^[A-Z][A-Z0-9_]{2,}\s*=/gm)} setting name(s) visible in the first part of the file. Values were not recorded.`,
        remediation: 'Remove the file from the web root, block dotfiles on the web server and rotate every secret it held.',
    },
    {
        path: '/.svn/entries', title: 'Subversion metadata exposed', severity: 'HIGH',
        signature: /^(\d{1,2}\s*$|dir\s*$)/m,
        remediation: 'Block access to /.svn and deploy from an export, not a working copy.',
    },
    {
        path: '/.DS_Store', title: 'macOS folder index exposed', severity: 'LOW',
        signature: /Bud1/,
        remediation: 'Delete .DS_Store files from the web root. They list file names in the folder.',
    },
    {
        path: '/phpinfo.php', title: 'PHP configuration page exposed', severity: 'HIGH',
        signature: /<title>phpinfo\(\)|PHP Version \d/i,
        remediation: 'Delete the page. It discloses versions, paths and environment values.',
    },
    {
        path: '/server-status', title: 'Apache server-status exposed', severity: 'MEDIUM',
        signature: /Apache Server Status for/i,
        remediation: 'Restrict mod_status to localhost or the management network.',
    },
    {
        path: '/actuator/env', title: 'Spring Boot actuator environment exposed', severity: 'HIGH',
        signature: /"propertySources"|"activeProfiles"/,
        summarise: () => 'The endpoint returned an environment document. Property values were not recorded.',
        remediation: 'Expose only the health endpoint publicly and put the rest behind authentication.',
    },
    {
        path: '/actuator', title: 'Spring Boot actuator index exposed', severity: 'MEDIUM',
        signature: /"_links"\s*:/,
        remediation: 'Limit management.endpoints.web.exposure.include to health and require authentication for the rest.',
    },
    {
        path: '/swagger.json', title: 'API schema published', severity: 'LOW',
        signature: /"(swagger|openapi)"\s*:/,
        summarise: (b) => `Roughly ${count(b, /"\/[^"]*"\s*:\s*\{/g)} path(s) listed in the first part of the document.`,
        remediation: 'Confirm the schema is meant to be public. It gives an attacker the full list of endpoints.',
    },
    {
        path: '/v3/api-docs', title: 'API schema published', severity: 'LOW',
        signature: /"openapi"\s*:/,
        remediation: 'Confirm the schema is meant to be public. It gives an attacker the full list of endpoints.',
    },
    {
        path: '/wp-json/wp/v2/users', title: 'WordPress user list readable', severity: 'MEDIUM',
        signature: /"slug"\s*:\s*"/,
        summarise: (b) => `${count(b, /"slug"\s*:/g)} account entry(ies) returned. Names were not recorded.`,
        remediation: 'Restrict the users endpoint to authenticated requests.',
    },
    {
        path: '/elmah.axd', title: 'ASP.NET error log exposed', severity: 'HIGH',
        signature: /Error Log for/i,
        remediation: 'Restrict ELMAH to authenticated administrators or remove the handler.',
    },
    {
        path: '/web.config', title: 'web.config served as a file', severity: 'HIGH',
        signature: /<configuration[\s>]/i,
        remediation: 'The server should never serve web.config. Fix the handler mapping and rotate any secrets inside it.',
    },
    {
        path: '/config.json', title: 'Configuration file exposed', severity: 'MEDIUM',
        signature: /"(password|secret|api_?key|token|connectionString)"\s*:/i,
        summarise: () => 'The file contains at least one secret-like setting name. Values were not recorded.',
        remediation: 'Move configuration out of the web root and rotate any secret it held.',
    },
    {
        path: '/composer.lock', title: 'Dependency manifest exposed', severity: 'LOW',
        signature: /"packages"\s*:\s*\[/,
        remediation: 'Block the file. It tells an attacker exactly which library versions are deployed.',
    },
    {
        path: '/package.json', title: 'Dependency manifest exposed', severity: 'LOW',
        signature: /"(dependencies|devDependencies)"\s*:\s*\{/,
        remediation: 'Block the file. It tells an attacker exactly which library versions are deployed.',
    },
    {
        path: '/phpmyadmin/', title: 'phpMyAdmin reachable from the internet', severity: 'HIGH',
        signature: /phpMyAdmin/,
        remediation: 'Put database administration behind a VPN or remove it.',
    },
    {
        path: '/jenkins/login', title: 'Jenkins sign-in reachable from the internet', severity: 'MEDIUM',
        signature: /Jenkins/,
        remediation: 'Put build tooling behind a VPN or single sign-on.',
    },
];

/** Paths in robots.txt that hint at sensitive areas. */
const INTERESTING = /admin|backup|private|internal|config|staging|secret|\.sql|\.bak|\.zip|old|test|dev/i;

/**
 * Web exposure scan. Requests a fixed list of well-known paths that should
 * never be public and reports a hit only when the body has the expected
 * structure. Every probe is a plain GET of a URL any visitor could type.
 * Nothing is submitted, no parameter is tampered with, and the evidence holds
 * counts and formats, never file contents.
 */
export const webExposureScan: Scenario = {
    id: 'web-exposure-scan',
    name: 'Web Exposure Scan',
    description: 'Look for files and consoles that should not be public (source control, environment files, debug and admin pages, API schemas) and confirm each hit by its content format. Read-only, contents never stored.',
    category: 'VULN',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Reconnaissance',
    attckTechnique: 'T1595.003 Wordlist Scanning',
    requiresActive: false,
    intrusive: true,
    tags: ['web', 'vuln', 'exposure', 'confirmation'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const webs = webTargetsFrom(await ensureServices(ctx));
        if (webs.length === 0) {
            return [{ title: 'No web services to check', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' }];
        }

        let probes = 0;
        for (const w of webs) {
            // Sites that answer 200 for anything would otherwise look vulnerable everywhere.
            const baseline = await httpGet(`${w.url}/miniasm-not-here-${Date.now()}`, { timeout: 5000, maxBody: 4096 });
            if (baseline.status === 0) continue;
            const catchAll = baseline.status === 200;

            for (const c of EXPOSURE_CHECKS) {
                const probe = await httpGet(w.url + c.path, { timeout: 5000, maxBody: 4096 });
                probes++;
                if (probe.status !== 200 || !c.signature.test(probe.bodySnippet)) continue;
                if (catchAll && c.signature.test(baseline.bodySnippet)) continue;
                results.push({
                    title: `${c.title}: ${c.path} on ${w.host}:${w.port}`,
                    severity: c.severity,
                    outcome: 'PROVEN',
                    target: w.url + c.path,
                    attckTactic: 'Reconnaissance',
                    attckTechnique: 'T1595.003 Wordlist Scanning',
                    evidence: `HTTP 200 and the body matched the expected format, which confirms the exposure is real. ${c.summarise ? c.summarise(probe.bodySnippet) : ''} Contents were not stored.`.replace(/\s+/g, ' ').trim(),
                    remediation: c.remediation,
                });
            }

            const robots = await httpGet(`${w.url}/robots.txt`, { timeout: 5000, maxBody: 4096 });
            if (robots.status === 200 && /disallow\s*:/i.test(robots.bodySnippet)) {
                const hints = [...robots.bodySnippet.matchAll(/^\s*disallow\s*:\s*(\S+)/gim)].map((m) => m[1]).filter((p) => INTERESTING.test(p));
                if (hints.length) {
                    results.push({
                        title: `robots.txt points at sensitive paths on ${w.host}:${w.port}`,
                        severity: 'LOW',
                        outcome: 'INFO',
                        target: `${w.url}/robots.txt`,
                        evidence: `Paths the site asks crawlers to skip: ${[...new Set(hints)].slice(0, 15).join(', ')}. Attackers read this file first.`,
                        remediation: 'Protect these paths with authentication. Hiding them in robots.txt advertises them.',
                    });
                }
            }

            const sec = await httpGet(`${w.url}/.well-known/security.txt`, { timeout: 5000, maxBody: 1024 });
            if (w.secure && !(sec.status === 200 && /^contact\s*:/im.test(sec.bodySnippet))) {
                results.push({
                    title: `No security.txt on ${w.host}:${w.port}`,
                    severity: 'INFO',
                    outcome: 'INFO',
                    target: `${w.url}/.well-known/security.txt`,
                    evidence: 'No contact file for security researchers was found.',
                    remediation: 'Publish /.well-known/security.txt (RFC 9116) so researchers can report issues to you.',
                });
            }
        }

        if (!results.some((r) => r.outcome === 'PROVEN')) {
            results.unshift({ title: 'No exposed files or consoles found', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: `Ran ${probes} check(s) across ${webs.length} web target(s); nothing sensitive was served.` });
        }
        return results;
    },
};
