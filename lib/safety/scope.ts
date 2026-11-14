import ipaddr from 'ipaddr.js';

export type ScopeKind = 'DOMAIN' | 'IP' | 'CIDR';

export interface ScopeItem {
    value: string;
    kind: ScopeKind;
    verified: boolean;
}

/**
 * Classify a raw scope string into DOMAIN, IP or CIDR.
 */
export function classifyScope(value: string): ScopeKind {
    const v = value.trim().toLowerCase();
    if (v.includes('/')) return 'CIDR';
    if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(v)) return 'IP';
    return 'DOMAIN';
}

function hostIsInDomainScope(host: string, scopeDomain: string): boolean {
    const h = host.trim().toLowerCase().replace(/\.$/, '');
    const d = scopeDomain.trim().toLowerCase().replace(/\.$/, '');
    return h === d || h.endsWith('.' + d);
}

function ipIsInCidr(ip: string, cidr: string): boolean {
    try {
        const addr = ipaddr.parse(ip);
        const range = ipaddr.parseCIDR(cidr);
        // Match address kinds (v4/v6) before comparing.
        if (addr.kind() !== range[0].kind()) return false;
        return addr.match(range as [ipaddr.IPv4 | ipaddr.IPv6, number]);
    } catch {
        return false;
    }
}

/**
 * Decide whether a target is inside a given scope list.
 *
 * `target` may be a domain, an IP, or a CIDR (we only allow a CIDR target if it
 * sits fully inside a scoped CIDR). A domain target matches a DOMAIN scope
 * entry if it is that domain or a subdomain of it. An IP target matches an IP
 * entry exactly, or any CIDR entry that contains it.
 */
export function isTargetInScope(target: string, scope: ScopeItem[]): { inScope: boolean; matched?: ScopeItem; reason: string } {
    const t = target.trim().toLowerCase().replace(/\.$/, '');
    const kind = classifyScope(t);

    for (const item of scope) {
        if (item.kind === 'DOMAIN' && (kind === 'DOMAIN')) {
            if (hostIsInDomainScope(t, item.value)) {
                return { inScope: true, matched: item, reason: `matched domain scope ${item.value}` };
            }
        }
        if (item.kind === 'IP' && kind === 'IP') {
            if (t === item.value.trim().toLowerCase()) {
                return { inScope: true, matched: item, reason: `matched IP scope ${item.value}` };
            }
        }
        if (item.kind === 'CIDR' && kind === 'IP') {
            if (ipIsInCidr(t, item.value)) {
                return { inScope: true, matched: item, reason: `IP inside CIDR ${item.value}` };
            }
        }
        if (item.kind === 'CIDR' && kind === 'CIDR') {
            // A CIDR target is in scope only if identical to a scoped CIDR.
            if (t === item.value.trim().toLowerCase()) {
                return { inScope: true, matched: item, reason: `matched CIDR scope ${item.value}` };
            }
        }
    }

    return { inScope: false, reason: `target "${target}" is not inside any scope entry` };
}

/**
 * Hard gate: a target may be touched by an ACTIVE scenario only if it is in
 * scope AND the matched scope entry has been ownership-verified.
 */
export function assertActiveAllowed(target: string, scope: ScopeItem[]): { allowed: boolean; reason: string } {
    const result = isTargetInScope(target, scope);
    if (!result.inScope) {
        return { allowed: false, reason: result.reason };
    }
    if (!result.matched?.verified) {
        return { allowed: false, reason: `scope entry "${result.matched?.value}" is not ownership-verified` };
    }
    return { allowed: true, reason: result.reason };
}
