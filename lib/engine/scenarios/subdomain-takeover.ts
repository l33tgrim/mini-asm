import dns from 'dns';
import type { Scenario, ScenarioResult } from '../types';
import { httpGet } from '../primitives';
import { classifyScope } from '@/lib/safety/scope';

const dnsp = dns.promises;

// CNAME targets commonly associated with dangling takeovers, and the fingerprint
// shown when the backing resource is unclaimed.
const TAKEOVER_SIGS: { cname: RegExp; fingerprint: RegExp; service: string }[] = [
    { cname: /\.github\.io$/i, fingerprint: /There isn't a GitHub Pages site here/i, service: 'GitHub Pages' },
    { cname: /\.herokuapp\.com$/i, fingerprint: /No such app/i, service: 'Heroku' },
    { cname: /\.s3[.-].*amazonaws\.com$/i, fingerprint: /NoSuchBucket/i, service: 'AWS S3' },
    { cname: /\.azurewebsites\.net$/i, fingerprint: /Web Site not found/i, service: 'Azure' },
    { cname: /\.cloudfront\.net$/i, fingerprint: /Bad request|ERROR: The request could not be satisfied/i, service: 'CloudFront' },
    { cname: /\.fastly\.net$/i, fingerprint: /Fastly error: unknown domain/i, service: 'Fastly' },
];

export const subdomainTakeover: Scenario = {
    id: 'subdomain-takeover',
    name: 'Subdomain Takeover',
    description: 'Check discovered subdomains for dangling CNAMEs pointing at unclaimed cloud resources.',
    category: 'EXPOSURE',
    maxSeverity: 'HIGH',
    attckTactic: 'Resource Development',
    attckTechnique: 'T1584.001 Domains',
    requiresActive: false,
    intrusive: false,
    tags: ['dns', 'takeover'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const hosts = new Set<string>();
        if (classifyScope(ctx.target) === 'DOMAIN') hosts.add(ctx.target);
        for (const s of (ctx.state.subdomains as string[] | undefined) || []) hosts.add(s);

        if (hosts.size === 0) {
            results.push({ title: 'No hosts to assess for takeover', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'Run recon first, or target a domain.' });
            return results;
        }

        for (const host of hosts) {
            let cnames: string[] = [];
            try { cnames = await dnsp.resolveCname(host); } catch { continue; }
            for (const cname of cnames) {
                const sig = TAKEOVER_SIGS.find((t) => t.cname.test(cname));
                if (!sig) continue;
                const probe = await httpGet(`http://${host}/`, { timeout: 6000, maxBody: 2048 });
                const dangling = sig.fingerprint.test(probe.bodySnippet);
                results.push({
                    title: `${dangling ? 'Likely' : 'Potential'} subdomain takeover: ${host}`,
                    severity: dangling ? 'HIGH' : 'MEDIUM',
                    outcome: dangling ? 'VULNERABLE' : 'INFO',
                    target: host,
                    attckTactic: 'Resource Development',
                    attckTechnique: 'T1584.001 Domains',
                    evidence: `${host} -> CNAME ${cname} (${sig.service}).${dangling ? ' Backing resource appears unclaimed (takeover fingerprint matched).' : ' Confirm the resource is claimed.'}`,
                    remediation: `Remove the dangling DNS record or reclaim the ${sig.service} resource.`,
                });
            }
        }
        if (results.length === 0) results.push({ title: 'No takeover candidates', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No dangling CNAMEs to known services found.' });
        return results;
    },
};
