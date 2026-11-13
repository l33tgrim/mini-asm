import crypto from 'crypto';
import dns from 'dns';

const dnsPromises = dns.promises;

export const DNS_TXT_PREFIX = '_miniasm-auth';
export const WELL_KNOWN_PATH = '/.well-known/miniasm-auth.txt';

/**
 * Generate an ownership-verification token for a scope entry. The operator
 * publishes this token (DNS TXT record or a well-known file) to prove they
 * control the asset before we run anything active against it.
 */
export function generateVerifyToken(): string {
    return 'miniasm-verify=' + crypto.randomBytes(24).toString('hex');
}

export interface VerifyResult {
    verified: boolean;
    method?: 'DNS_TXT' | 'WELL_KNOWN';
    detail: string;
}

async function checkDnsTxt(domain: string, token: string): Promise<boolean> {
    try {
        const records = await dnsPromises.resolveTxt(`${DNS_TXT_PREFIX}.${domain}`);
        const flat = records.map((chunks) => chunks.join('')).map((s) => s.trim());
        return flat.includes(token);
    } catch {
        return false;
    }
}

async function checkWellKnown(domain: string, token: string): Promise<boolean> {
    for (const scheme of ['https', 'http']) {
        try {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), 6000);
            const res = await fetch(`${scheme}://${domain}${WELL_KNOWN_PATH}`, {
                signal: controller.signal,
                redirect: 'manual',
            }).catch(() => null);
            clearTimeout(id);
            if (res && res.ok) {
                const body = (await res.text()).trim();
                if (body.split(/\s+/).includes(token) || body === token) return true;
            }
        } catch {
            /* try next scheme */
        }
    }
    return false;
}

/**
 * Verify ownership of a domain scope entry against a published token.
 * Only domains are verifiable this way; bare IPs and CIDRs must be authorized
 * out of band (recorded on the engagement by an operator with authority).
 */
export async function verifyDomainOwnership(domain: string, token: string): Promise<VerifyResult> {
    if (await checkDnsTxt(domain, token)) {
        return { verified: true, method: 'DNS_TXT', detail: `found token in ${DNS_TXT_PREFIX}.${domain} TXT record` };
    }
    if (await checkWellKnown(domain, token)) {
        return { verified: true, method: 'WELL_KNOWN', detail: `found token at ${domain}${WELL_KNOWN_PATH}` };
    }
    return {
        verified: false,
        detail: `token not found. Publish TXT "${DNS_TXT_PREFIX}.${domain}" = "${token}" OR host it at ${domain}${WELL_KNOWN_PATH}`,
    };
}
