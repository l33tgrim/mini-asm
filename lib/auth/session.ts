/**
 * Signed session cookies for the sign-in page. Uses Web Crypto so the same
 * code runs in the proxy and in route handlers.
 *
 * A token is `base64url(username).expiry.signature`. The signing key comes from
 * ASM_SESSION_SECRET when set, otherwise it is derived from the configured
 * credentials, so changing the password signs everyone out.
 */

export const SESSION_COOKIE = 'asm_session';
export const SESSION_HOURS = 12;

const enc = new TextEncoder();

export interface Credentials {
    username: string;
    password: string;
}

export function configuredCredentials(): Credentials | null {
    const username = process.env.ASM_USERNAME;
    const password = process.env.ASM_PASSWORD;
    return username && password ? { username, password } : null;
}

export function authDisabled(): boolean {
    if (configuredCredentials()) return false;
    return process.env.ASM_AUTH_DISABLED === 'true' || process.env.NODE_ENV !== 'production';
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (const b of arr) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(s: string): string {
    const pad = s.replace(/-/g, '+').replace(/_/g, '/');
    return new TextDecoder().decode(Uint8Array.from(atob(pad + '='.repeat((4 - (pad.length % 4)) % 4)), (c) => c.charCodeAt(0)));
}

async function key(creds: Credentials): Promise<CryptoKey> {
    const material = process.env.ASM_SESSION_SECRET || `${creds.username}\u0000${creds.password}\u0000mini-asm-session`;
    const digest = await crypto.subtle.digest('SHA-256', enc.encode(material));
    return crypto.subtle.importKey('raw', digest, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

/** Compare two strings without leaking where they differ. */
export function safeEqual(a: string, b: string): boolean {
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return diff === 0;
}

export function credentialsMatch(creds: Credentials, username: string, password: string): boolean {
    const userOk = safeEqual(username, creds.username);
    const passOk = safeEqual(password, creds.password);
    return userOk && passOk;
}

export async function createSession(creds: Credentials, now = Date.now()): Promise<string> {
    const payload = `${b64url(enc.encode(creds.username))}.${now + SESSION_HOURS * 3600_000}`;
    const sig = await crypto.subtle.sign('HMAC', await key(creds), enc.encode(payload));
    return `${payload}.${b64url(sig)}`;
}

/** Returns the signed-in username, or null when the token is missing, forged or expired. */
export async function verifySession(token: string | undefined, creds: Credentials, now = Date.now()): Promise<string | null> {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [user, expiry, sig] = parts;
    const expected = b64url(await crypto.subtle.sign('HMAC', await key(creds), enc.encode(`${user}.${expiry}`)));
    if (!safeEqual(sig, expected)) return null;
    if (!(Number(expiry) > now)) return null;
    try {
        const name = fromB64url(user);
        return safeEqual(name, creds.username) ? name : null;
    } catch {
        return null;
    }
}

/** Only allow redirects back into this app after sign-in. */
export function safeNextPath(next: string | null | undefined): string {
    if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\') || next.startsWith('/login')) return '/';
    return next;
}
