import { getTargetIps, scanIp } from '@/lib/scanner';
import type { RunContext } from '../types';

export interface ServiceRef {
    ip: string;
    port: number;
    service: string;
    banner?: string;
    version?: string;
    domains?: string;
}

export interface WebTarget {
    url: string;
    host: string;
    port: number;
    secure: boolean;
}

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888]);

/**
 * Resolve the target to IPs and discover listening services, once per run.
 * Cached on the shared state bag so a playbook does recon a single time and
 * every later scenario reuses it.
 */
export async function ensureServices(ctx: RunContext): Promise<ServiceRef[]> {
    if (Array.isArray(ctx.state.services)) return ctx.state.services as ServiceRef[];

    const { ips, mappings } = await getTargetIps(ctx.target);
    ctx.state.ips = ips;

    const services: ServiceRef[] = [];
    for (const ip of ips.slice(0, 16)) {
        const hostname = mappings[ip] && mappings[ip].length ? mappings[ip][0] : undefined;
        try {
            const res = await scanIp(ip, hostname);
            for (const r of res) {
                services.push({
                    ip: r.ip,
                    port: r.port,
                    service: r.service,
                    banner: r.banner,
                    version: r.version,
                    domains: r.domains || hostname,
                });
            }
        } catch (e) {
            ctx.log(`scanIp failed for ${ip}: ${(e as Error).message}`);
        }
    }
    ctx.state.services = services;
    return services;
}

export function webTargetsFrom(services: ServiceRef[]): WebTarget[] {
    const out: WebTarget[] = [];
    for (const s of services) {
        if (!WEB_PORTS.has(s.port)) continue;
        const secure = s.port === 443 || s.port === 8443;
        const host = s.domains?.split(',')[0] || s.ip;
        out.push({ url: `${secure ? 'https' : 'http'}://${host}:${s.port}`, host, port: s.port, secure });
    }
    return out;
}

// Typed parameter readers: scenarios pull config from ctx.params with a default.
export function paramString(ctx: RunContext, key: string, def = ''): string {
    const v = ctx.params[key];
    return typeof v === 'string' ? v : def;
}

export function paramList(ctx: RunContext, key: string, def: string[] = []): string[] {
    const v = ctx.params[key];
    if (Array.isArray(v)) return v.map(String);
    if (typeof v === 'string') return v.split(',').map((s) => s.trim()).filter(Boolean);
    return def;
}

export function paramJson<T>(ctx: RunContext, key: string, def: T): T {
    const v = ctx.params[key];
    if (v === undefined || v === null) return def;
    if (typeof v === 'string') {
        try {
            return JSON.parse(v) as T;
        } catch {
            return def;
        }
    }
    return v as T;
}
