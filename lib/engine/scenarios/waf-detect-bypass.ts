import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

// WAF/CDN fingerprints keyed on response headers.
const WAF_SIGNATURES: { name: string; header: string; value?: RegExp }[] = [
    { name: 'Cloudflare', header: 'cf-ray' },
    { name: 'Cloudflare', header: 'server', value: /cloudflare/i },
    { name: 'Akamai', header: 'x-akamai-transformed' },
    { name: 'AWS CloudFront', header: 'x-amz-cf-id' },
    { name: 'AWS WAF', header: 'x-amzn-waf-action' },
    { name: 'Imperva Incapsula', header: 'x-iinfo' },
    { name: 'Sucuri', header: 'x-sucuri-id' },
    { name: 'F5 BIG-IP', header: 'server', value: /big-?ip/i },
    { name: 'Fastly', header: 'x-served-by', value: /cache/i },
];

// Benign canary payloads. These are shaped like attacks so the WAF SHOULD block
// them, but they do nothing even if they reach the app. We measure block vs pass.
const CANARIES: { name: string; qs: string; category: string }[] = [
    { name: 'XSS canary', qs: 'q=<script>miniasm-canary</script>', category: 'XSS' },
    { name: 'SQLi canary', qs: "q=1' OR '1'='1", category: 'SQLi' },
    { name: 'Union canary', qs: 'q=1 UNION SELECT NULL-- -', category: 'SQLi' },
    { name: 'Traversal canary', qs: 'file=../../../../etc/passwd', category: 'Path Traversal' },
    { name: 'Command canary', qs: 'cmd=;id', category: 'Command Injection' },
];

export const wafDetectBypass: Scenario = {
    id: 'waf-detect-bypass',
    name: 'WAF Detection & Rule Coverage',
    description: 'Fingerprint the WAF/CDN, measure which attack categories it blocks using benign canaries, and flag origin exposure that bypasses it.',
    category: 'WAF',
    maxSeverity: 'HIGH',
    attckTactic: 'Defense Evasion',
    attckTechnique: 'T1090 Proxy / T1600 Weaken Encryption',
    requiresActive: true,
    intrusive: true,
    tags: ['waf', 'bypass', 'origin'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        const webs = webTargetsFrom(services).filter((w) => w.secure || w.port === 80);

        if (webs.length === 0) {
            results.push({ title: 'No web services to test for WAF', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No HTTP/HTTPS services found.' });
            return results;
        }

        for (const w of webs.slice(0, 4)) {
            // Fingerprint.
            const base = await httpGet(w.url, { timeout: 6000 });
            const detected = new Set<string>();
            for (const sig of WAF_SIGNATURES) {
                const h = base.headers[sig.header];
                if (h && (!sig.value || sig.value.test(h))) detected.add(sig.name);
            }
            const wafName = detected.size ? Array.from(detected).join(', ') : 'none detected';
            results.push({
                title: `WAF/CDN fingerprint for ${w.host}:${w.port}`,
                severity: detected.size ? 'INFO' : 'LOW',
                outcome: detected.size ? 'SECURE' : 'INFO',
                target: w.url,
                attckTactic: 'Defense Evasion',
                evidence: detected.size ? `Fronted by: ${wafName}` : 'No WAF/CDN fingerprint in response headers. The app may be directly exposed.',
                remediation: detected.size ? undefined : 'Consider placing the app behind a WAF/CDN.',
            });

            // Canary block-rate measurement.
            let blocked = 0;
            const detail: string[] = [];
            for (const c of CANARIES) {
                const probe = await httpGet(`${w.url}/?${c.qs}`, { timeout: 6000 });
                const isBlocked = probe.status === 403 || probe.status === 406 || probe.status === 429 || /access denied|request blocked|attention required/i.test(probe.bodySnippet);
                if (isBlocked) blocked++;
                detail.push(`${c.category}: ${isBlocked ? 'BLOCKED' : `passed (HTTP ${probe.status})`}`);
            }
            const coverage = Math.round((blocked / CANARIES.length) * 100);
            results.push({
                title: `WAF rule coverage ${coverage}% on ${w.host}:${w.port}`,
                severity: coverage >= 80 ? 'INFO' : coverage >= 40 ? 'MEDIUM' : 'HIGH',
                outcome: coverage >= 80 ? 'SECURE' : 'VULNERABLE',
                target: w.url,
                attckTactic: 'Defense Evasion',
                attckTechnique: 'T1190 Exploit Public-Facing Application',
                evidence: `Benign canaries blocked: ${blocked}/${CANARIES.length} (${coverage}%).\n${detail.join('\n')}`,
                remediation: coverage >= 80 ? undefined : 'Tune WAF rules to cover the categories that passed. Payloads here were benign measurement probes.',
            });
        }

        // Origin exposure: an in-scope IP that answers directly bypasses a WAF.
        const directIps = (ctx.state.ips as string[] | undefined) || [];
        if (detectedAnyWaf(results) && directIps.length > 0) {
            results.push({
                title: 'Possible origin IP exposure behind WAF',
                severity: 'HIGH',
                outcome: 'VULNERABLE',
                target: ctx.target,
                attckTactic: 'Defense Evasion',
                attckTechnique: 'T1090 Proxy',
                evidence: `Resolved IPs that may be the origin behind the WAF: ${directIps.slice(0, 8).join(', ')}. If these answer the app directly, every WAF rule is bypassed.`,
                remediation: 'Lock origin firewalls so the app only accepts traffic from the WAF/CDN IP ranges.',
            });
        }
        return results;
    },
};

function detectedAnyWaf(results: ScenarioResult[]): boolean {
    return results.some((r) => r.title.startsWith('WAF/CDN fingerprint') && r.outcome === 'SECURE');
}
