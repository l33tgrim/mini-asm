import type { Scenario, ScenarioResult } from '../types';
import { resolveDomain } from '@/lib/scanner';
import { ensureServices } from './_shared';
import { classifyScope } from '@/lib/safety/scope';

/**
 * Passive-leaning external footprint: what of this asset is reachable from the
 * internet. DNS, subdomains, and the set of listening services.
 */
export const reconExposure: Scenario = {
    id: 'recon-exposure',
    name: 'Internet Exposure Mapping',
    description: 'Resolve DNS, discover subdomains, and enumerate internet-facing services and open ports.',
    category: 'RECON',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Reconnaissance',
    attckTechnique: 'T1595 Active Scanning',
    requiresActive: false,
    intrusive: false,
    tags: ['asm', 'discovery', 'ports'],
    async run(ctx) {
        const results: ScenarioResult[] = [];

        if (classifyScope(ctx.target) === 'DOMAIN') {
            const { ips, details, subdomains } = await resolveDomain(ctx.target);
            ctx.state.subdomains = subdomains;
            results.push({
                title: `DNS footprint for ${ctx.target}`,
                severity: 'INFO',
                outcome: 'INFO',
                target: ctx.target,
                attckTactic: 'Reconnaissance',
                attckTechnique: 'T1590 Gather Victim Network Information',
                evidence: [`Resolved ${ips.length} IPs, ${subdomains.length} subdomains`, ...details.slice(0, 40)].join('\n'),
            });
            if (subdomains.length > 0) {
                results.push({
                    title: `${subdomains.length} subdomains discovered`,
                    severity: subdomains.length > 10 ? 'MEDIUM' : 'LOW',
                    outcome: 'INFO',
                    target: ctx.target,
                    attckTactic: 'Reconnaissance',
                    attckTechnique: 'T1595.003 Wordlist Scanning',
                    evidence: subdomains.join('\n'),
                    remediation: 'Confirm every discovered subdomain is intended to be public and is actively maintained. Retire stale hosts.',
                });
            }
        }

        const services = await ensureServices(ctx);
        if (services.length === 0) {
            results.push({
                title: 'No listening services found',
                severity: 'INFO',
                outcome: 'SECURE',
                target: ctx.target,
                evidence: 'No responsive TCP services on the common port set.',
            });
            return results;
        }

        const summary = services
            .map((s) => `${s.ip}:${s.port} ${s.service}${s.version ? ' ' + s.version : ''}`)
            .join('\n');
        results.push({
            title: `${services.length} internet-facing services`,
            severity: services.length > 8 ? 'MEDIUM' : 'LOW',
            outcome: 'INFO',
            target: ctx.target,
            attckTactic: 'Reconnaissance',
            attckTechnique: 'T1595.002 Vulnerability Scanning',
            evidence: summary,
            remediation: 'Reduce the exposed surface: close or firewall any service that does not need to face the internet.',
        });
        return results;
    },
};
