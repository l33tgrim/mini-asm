import dns from 'dns';
import type { Scenario, ScenarioResult } from '../types';
import { classifyScope } from '@/lib/safety/scope';
import { providerFor, registrableDomain } from '@/lib/discovery';

const dnsp = dns.promises;

/** TXT records for a name, or null when the lookup itself failed (timeout, SERVFAIL). */
async function txt(name: string): Promise<string[] | null> {
    try {
        return (await dnsp.resolveTxt(name)).map((c) => c.join(''));
    } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        return code === 'ENODATA' || code === 'ENOTFOUND' ? [] : null;
    }
}

/** The DMARC policy tag, not sp= or the other tags that end in p. */
export function dmarcPolicy(record: string, subdomain = false): string {
    const tags = new Map(record.split(';').map((t) => t.trim().split('=').map((v) => v.trim().toLowerCase()) as [string, string]));
    const p = tags.get('p') || 'none';
    return subdomain ? tags.get('sp') || p : p;
}

/** The redirect= target of an SPF record, if it hands off to another record. */
export function spfRedirect(record: string): string | null {
    return record.match(/(?:^|\s)redirect=([^\s]+)/i)?.[1]?.toLowerCase() ?? null;
}

/** Hosted SPF or DMARC services named in a record or alias, e.g. Sendmarc. */
export function emailProviders(...values: string[]): string[] {
    const names = values.flatMap((v) => v.toLowerCase().match(/[a-z0-9.-]+\.[a-z]{2,}/g) ?? []);
    return Array.from(new Set(names.map((n) => providerFor(n.replace(/^[^a-z0-9]+/, ''))).filter((p): p is string => !!p)));
}

async function cname(name: string): Promise<string[]> {
    return dnsp.resolveCname(name).catch(() => []);
}

/** SPF all mechanism, read from the end of the record. */
export function spfAll(record: string): string | null {
    const m = record.toLowerCase().match(/(?:^|\s)([+?~-]?)all(?:\s|$)/);
    return m ? (m[1] || '+') : null;
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

        const host = ctx.target.replace(/\.$/, '').toLowerCase();
        // Mail is sent from the organisation domain, so www.example.co.za is
        // judged by the records on example.co.za. DMARC falls back to the
        // organisation domain the same way receivers do (RFC 7489 section 6.6.3).
        const org = registrableDomain(host) || host;
        const isSub = org !== host;
        const [hostTxt, hostDmarc, orgTxt, orgDmarc] = await Promise.all([
            txt(host), txt(`_dmarc.${host}`), isSub ? txt(org) : Promise.resolve(null), isSub ? txt(`_dmarc.${org}`) : Promise.resolve(null),
        ]);
        if (hostTxt === null && (!isSub || orgTxt === null)) {
            results.push({ title: 'Email records could not be read', severity: 'INFO', outcome: 'ERROR', target: host, evidence: `The DNS lookup for ${host} failed, so SPF and DMARC were not judged.` });
            return results;
        }

        const findSpf = (records: string[] | null) => records?.find((r) => r.toLowerCase().startsWith('v=spf1'));
        const findDmarc = (records: string[] | null) => records?.find((r) => r.toLowerCase().startsWith('v=dmarc1'));

        let spf = findSpf(hostTxt);
        let spfAt = host;
        if (!spf && isSub) { spf = findSpf(orgTxt); spfAt = org; }

        // Hosted SPF often ends in redirect= instead of an all mechanism, so
        // the provider's record decides the policy.
        let effective = spf;
        const chain: string[] = [];
        for (let hop = 0; effective && !spfAll(effective) && hop < 3; hop++) {
            const next = spfRedirect(effective);
            if (!next) break;
            chain.push(next);
            effective = findSpf(await txt(next));
        }
        const spfVia = chain.length > 0 ? `\nFollows redirect to ${chain.join(' -> ')}${effective ? `: ${effective}` : ' (record not found)'}` : '';
        const spfHosts = spf ? emailProviders(spf, ...chain) : [];
        const spfManaged = spfHosts.length > 0 ? `\nManaged by ${spfHosts.join(', ')}` : '';

        if (!spf) {
            results.push({ title: 'No SPF record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: org, attckTechnique: 'T1566 Phishing', evidence: `No v=spf1 TXT record on ${isSub ? `${host} or ${org}` : host}.`, remediation: 'Publish an SPF record listing authorised senders and end it with -all.' });
        } else if (['+', '?'].includes(spfAll(effective ?? spf) ?? '')) {
            results.push({ title: 'Permissive SPF record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: spfAt, evidence: `SPF permits unlisted senders: ${spf}${spfVia}${spfManaged}`, remediation: 'Tighten SPF to -all (hard fail).' });
        } else {
            results.push({ title: 'SPF present', severity: 'INFO', outcome: 'SECURE', target: spfAt, evidence: `${spf}${spfVia}${spfManaged}` });
        }

        let dmarc = findDmarc(hostDmarc);
        let dmarcAt = host;
        if (!dmarc && isSub) { dmarc = findDmarc(orgDmarc); dmarcAt = org; }

        if (!dmarc) {
            results.push({ title: 'No DMARC record', severity: 'MEDIUM', outcome: 'VULNERABLE', target: org, attckTechnique: 'T1566 Phishing', evidence: `No v=DMARC1 record at _dmarc.${host}${isSub ? ` or _dmarc.${org}` : ''}.`, remediation: 'Publish a DMARC record, start at p=none to monitor, then move to p=quarantine/reject.' });
        } else {
            const inherited = dmarcAt !== host;
            const policy = dmarcPolicy(dmarc, inherited);
            // Hosted DMARC is usually a CNAME from _dmarc to the provider.
            const alias = await cname(`_dmarc.${dmarcAt}`);
            const dmarcHosts = emailProviders(dmarc, ...alias);
            const evidence = [
                dmarc,
                alias.length > 0 ? `_dmarc.${dmarcAt} is an alias for ${alias.join(' -> ')}` : '',
                dmarcHosts.length > 0 ? `Managed by ${dmarcHosts.join(', ')}` : '',
                inherited ? `(${host} is covered by the record on _dmarc.${org})` : '',
            ].filter(Boolean).join('\n');
            if (policy === 'none') {
                results.push({ title: 'DMARC policy is monitor-only (p=none)', severity: 'LOW', outcome: 'VULNERABLE', target: dmarcAt, evidence, remediation: 'Move DMARC to p=quarantine then p=reject once reporting is clean.' });
            } else {
                results.push({ title: `DMARC enforced (p=${policy})`, severity: 'INFO', outcome: 'SECURE', target: dmarcAt, evidence });
            }
        }
        return results;
    },
};
