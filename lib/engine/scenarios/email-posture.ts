import dns from 'dns';
import type { Scenario, ScenarioResult } from '../types';
import { classifyScope } from '@/lib/safety/scope';

const dnsp = dns.promises;

async function txt(name: string): Promise<string[]> {
    try {
        return (await dnsp.resolveTxt(name)).map((c) => c.join(''));
    } catch {
        return [];
    }
}

/**
 * Email spoofing posture: SPF, DMARC, DMARC policy strength. A weak or absent
 * DMARC policy means an attacker can spoof mail from the domain.
 */
export const emailPosture: Scenario = {
    id: 'email-posture',
    name: 'Email Spoofing Posture (SPF/DMARC)',
    description: 'Check SPF and DMARC records and flag weak or missing anti-spoofing policy.',
    category: 'POSTURE',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1566 Phishing',
    requiresActive: false,
    intrusive: false,
    tags: ['email', 'spoofing', 'dmarc'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        if (classifyScope(ctx.target) !== 'DOMAIN') {
            results.push({ title: 'Email posture needs a domain', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'Target is not a domain; skipping SPF/DMARC.' });
            return results;
        }

        const domain = ctx.target.replace(/\.$/, '');
        const root = txt(domain);
        const dmarc = txt(`_dmarc.${domain}`);
        const [rootTxt, dmarcTxt] = await Promise.all([root, dmarc]);

        const spf = rootTxt.find((r) => r.toLowerCase().includes('v=spf1'));
        const dmarcRec = dmarcTxt.find((r) => r.toLowerCase().includes('v=dmarc1'));

        if (!spf) {
            results.push({ title: 'No SPF record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: domain, attckTechnique: 'T1566 Phishing', evidence: 'No v=spf1 TXT record found.', remediation: 'Publish an SPF record listing authorised senders and end it with -all.' });
        } else if (spf.includes('+all') || spf.includes('?all')) {
            results.push({ title: 'Permissive SPF record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: domain, evidence: `SPF permits unlisted senders: ${spf}`, remediation: 'Tighten SPF to -all (hard fail).' });
        } else {
            results.push({ title: 'SPF present', severity: 'INFO', outcome: 'SECURE', target: domain, evidence: spf });
        }

        if (!dmarcRec) {
            results.push({ title: 'No DMARC record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: domain, attckTechnique: 'T1566 Phishing', evidence: 'No v=DMARC1 record at _dmarc.' + domain, remediation: 'Publish a DMARC record, start at p=none to monitor, then move to p=quarantine/reject.' });
        } else {
            const policy = (dmarcRec.match(/p=(\w+)/)?.[1] || 'none').toLowerCase();
            if (policy === 'none') {
                results.push({ title: 'DMARC policy is monitor-only (p=none)', severity: 'LOW', outcome: 'VULNERABLE', target: domain, evidence: dmarcRec, remediation: 'Move DMARC to p=quarantine then p=reject once reporting is clean.' });
            } else {
                results.push({ title: `DMARC enforced (p=${policy})`, severity: 'INFO', outcome: 'SECURE', target: domain, evidence: dmarcRec });
            }
        }
        return results;
    },
};
