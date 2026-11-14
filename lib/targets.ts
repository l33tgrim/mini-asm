import net from 'net';
import ipaddr from 'ipaddr.js';

/** Raised for anything wrong with a user supplied target. The message is safe to show in the UI. */
export class TargetError extends Error {}

export type ParsedTarget =
    | { kind: 'ip'; value: string }
    | { kind: 'cidr'; value: string; ips: string[] }
    | { kind: 'domain'; value: string };

export const MAX_TARGET_LENGTH = 253;
export const MAX_IPS_PER_SCAN = 256;

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

// Ranges that are never a legitimate scan target for this tool. Loopback and
// link-local in particular would let a caller probe the server hosting the app
// or a cloud metadata endpoint.
const BLOCKED_RANGES = new Set(['unspecified', 'loopback', 'linkLocal', 'multicast', 'broadcast', 'reserved']);

export function isScannableIp(ip: string): boolean {
    if (!net.isIPv4(ip)) return false;
    try {
        return !BLOCKED_RANGES.has(ipaddr.IPv4.parse(ip).range());
    } catch {
        return false;
    }
}

export function isDomainTarget(target: string): boolean {
    return DOMAIN_RE.test(target.toLowerCase());
}

function expandCidr(cidr: string): string[] {
    let prefix: number;
    try {
        const [addr, bits] = ipaddr.parseCIDR(cidr);
        if (addr.kind() !== 'ipv4') throw new TargetError('Only IPv4 ranges are supported.');
        prefix = bits;
    } catch (e) {
        if (e instanceof TargetError) throw e;
        throw new TargetError('That is not a valid CIDR range.');
    }
    if (prefix < 24) {
        throw new TargetError('Ranges larger than /24 are not supported. Split the range into /24 blocks.');
    }

    const base = ipaddr.IPv4.networkAddressFromCIDR(cidr).toByteArray();
    const size = 2 ** (32 - prefix);
    // /31 and /32 have no network or broadcast address to skip.
    const first = size > 2 ? 1 : 0;
    const last = size > 2 ? size - 2 : size - 1;

    const ips: string[] = [];
    for (let i = first; i <= last; i++) {
        ips.push(`${base[0]}.${base[1]}.${base[2]}.${base[3] + i}`);
    }
    return ips;
}

export function parseTarget(raw: unknown): ParsedTarget {
    if (typeof raw !== 'string') throw new TargetError('Target is required.');
    const target = raw.trim().toLowerCase();
    if (!target) throw new TargetError('Target is required.');
    if (target.length > MAX_TARGET_LENGTH) throw new TargetError('Target is too long.');

    if (target.includes('/')) {
        const ips = expandCidr(target);
        if (!ips.every(isScannableIp)) {
            throw new TargetError('That range covers loopback, link-local or reserved addresses and cannot be scanned.');
        }
        return { kind: 'cidr', value: target, ips };
    }

    if (net.isIPv4(target)) {
        if (!isScannableIp(target)) {
            throw new TargetError('Loopback, link-local and reserved addresses cannot be scanned.');
        }
        return { kind: 'ip', value: target };
    }

    if (net.isIPv6(target)) throw new TargetError('IPv6 targets are not supported yet.');

    if (DOMAIN_RE.test(target)) return { kind: 'domain', value: target };

    throw new TargetError('Enter a domain (example.com), an IPv4 address, or a CIDR range of /24 or smaller.');
}
