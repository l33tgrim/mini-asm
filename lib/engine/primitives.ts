import net from 'net';
import dns from 'dns';
import { isScannableIp } from '@/lib/targets';
import { acquire } from '@/lib/safety/ratelimit';
import { assertNotKilled } from '@/lib/safety/killswitch';

/**
 * Safe, read-only network primitives shared by scenarios. Every call is
 * rate-limited per host and checks the kill switch first. None of these
 * mutate state on the target.
 */

const hostChecks = new Map<string, { ok: boolean; at: number }>();

/**
 * Refuse hosts that are, or resolve to, loopback, link-local or reserved
 * addresses. An in-scope name can point anywhere, including at this server or
 * a cloud metadata endpoint, so every primitive checks before connecting.
 */
export async function assertSafeHost(host: string): Promise<void> {
    const key = host.toLowerCase();
    const cached = hostChecks.get(key);
    let ok: boolean;
    if (cached && Date.now() - cached.at < 60_000) {
        ok = cached.ok;
    } else {
        if (net.isIP(key)) {
            ok = isScannableIp(key);
        } else {
            const addrs = await dns.promises.lookup(key, { all: true }).catch(() => []);
            ok = addrs.length > 0 && addrs.every((a) => isScannableIp(a.address));
        }
        hostChecks.set(key, { ok, at: Date.now() });
    }
    if (!ok) throw new Error(`UNSAFE_HOST: ${host} is or resolves to a non-routable or unsupported address`);
}

export async function tcpConnect(host: string, port: number, timeout = 1500): Promise<boolean> {
    assertNotKilled();
    await assertSafeHost(host);
    await acquire(host);
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const fail = () => {
            socket.destroy();
            resolve(false);
        };
        socket.setTimeout(timeout);
        socket.once('error', fail);
        socket.once('timeout', fail);
        socket.connect(port, host, () => {
            socket.end();
            resolve(true);
        });
    });
}

export async function grabBanner(host: string, port: number, timeout = 3000): Promise<string | null> {
    assertNotKilled();
    await assertSafeHost(host);
    await acquire(host);
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let done = false;
        const finish = (r: string | null) => {
            if (done) return;
            done = true;
            socket.destroy();
            resolve(r);
        };
        socket.setTimeout(timeout);
        socket.once('error', () => finish(null));
        socket.once('timeout', () => finish(data || null));
        socket.connect(port, host, () => {
            if (port === 80 || port === 8080) socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
        });
        socket.on('data', (chunk) => {
            data += chunk.toString();
            if (port !== 80 && port !== 443 && port !== 8080) finish(data);
            if (data.length > 2048) finish(data);
        });
        socket.on('end', () => finish(data || null));
    });
}

export interface HttpProbe {
    ok: boolean;
    status: number;
    headers: Record<string, string>;
    bodySnippet: string;
    error?: string;
}

export async function httpGet(
    url: string,
    opts: { headers?: Record<string, string>; timeout?: number; method?: string; maxBody?: number } = {}
): Promise<HttpProbe> {
    assertNotKilled();
    const host = (() => {
        try {
            return new URL(url).hostname;
        } catch {
            return url;
        }
    })();
    await assertSafeHost(host);
    await acquire(host);

    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), opts.timeout ?? 6000);
    try {
        const res = await fetch(url, {
            method: opts.method ?? 'GET',
            headers: opts.headers,
            signal: controller.signal,
            redirect: 'manual',
        });
        clearTimeout(id);
        const headers: Record<string, string> = {};
        res.headers.forEach((v, k) => (headers[k] = v));
        const text = await res.text().catch(() => '');
        return {
            ok: res.ok,
            status: res.status,
            headers,
            bodySnippet: text.slice(0, opts.maxBody ?? 1024),
        };
    } catch (e: unknown) {
        clearTimeout(id);
        return { ok: false, status: 0, headers: {}, bodySnippet: '', error: (e as Error).message };
    }
}

/**
 * Send a single read-only Redis command over RESP. Only a hard-coded set of
 * non-mutating commands is permitted; anything else throws.
 */
const REDIS_READONLY = new Set(['PING', 'INFO', 'DBSIZE', 'TIME', 'COMMAND COUNT']);

export async function redisReadOnly(host: string, port: number, command: string, timeout = 4000): Promise<string | null> {
    assertNotKilled();
    const cmd = command.trim().toUpperCase();
    if (!REDIS_READONLY.has(cmd)) {
        throw new Error(`redis command "${command}" is not read-only / allowed`);
    }
    await assertSafeHost(host);
    await acquire(host);
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let done = false;
        const finish = (r: string | null) => {
            if (done) return;
            done = true;
            socket.destroy();
            resolve(r);
        };
        socket.setTimeout(timeout);
        socket.once('error', () => finish(null));
        socket.once('timeout', () => finish(data || null));
        socket.connect(port, host, () => {
            // inline command protocol is fine for simple read-only commands
            socket.write(command + '\r\n');
        });
        socket.on('data', (chunk) => {
            data += chunk.toString();
            if (data.length > 4096) finish(data);
        });
    });
}
