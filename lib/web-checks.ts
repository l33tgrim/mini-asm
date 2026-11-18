import type { Severity } from './ports';

export interface HeaderIssue {
    text: string;
    severity: Severity;
    fix: string;
}

export interface HeaderSource {
    get(name: string): string | null;
    getSetCookie?(): string[];
}

/**
 * Checks the response headers of one page load. Pure, so it can be tested
 * without a network. Severities stay low: these are hygiene findings, not
 * proof that anything is exploitable.
 */
export function headerIssues(protocol: 'http' | 'https', status: number, headers: HeaderSource): HeaderIssue[] {
    const issues: HeaderIssue[] = [];
    const isRedirect = status >= 300 && status < 400;
    const location = (headers.get('location') || '').trim();

    if (protocol === 'http') {
        if (!(isRedirect && /^https:\/\//i.test(location))) {
            issues.push({ text: 'Content served over unencrypted HTTP', severity: 'LOW', fix: 'Redirect all HTTP traffic to HTTPS.' });
        }
    } else {
        if (isRedirect && /^http:\/\//i.test(location)) {
            issues.push({
                text: `HTTPS redirects to an insecure address (${location.slice(0, 120)})`,
                severity: 'MEDIUM',
                fix: 'Point the redirect at an https:// address so visitors are not dropped back to plain HTTP.',
            });
        }
        if (!headers.get('strict-transport-security')) {
            issues.push({ text: 'Missing Strict-Transport-Security header', severity: 'LOW', fix: 'Send a Strict-Transport-Security header so browsers always use HTTPS.' });
        }
    }

    const server = (headers.get('server') || '').trim();
    const poweredBy = (headers.get('x-powered-by') || '').trim();
    const leaked = [server, poweredBy].filter((h) => /\d+\.\d+/.test(h));
    if (leaked.length > 0) {
        issues.push({
            text: `Server header reveals software versions (${leaked.join(', ').slice(0, 120)})`,
            severity: 'LOW',
            fix: 'Hide version numbers in the Server and X-Powered-By headers (for example server_tokens off in nginx, ServerTokens Prod in Apache).',
        });
    }

    const cookies = cookieIssues(headers.getSetCookie?.() ?? [], protocol);
    issues.push(...cookies);

    if (!isRedirect) {
        const csp = headers.get('content-security-policy') || '';
        if (!csp) {
            issues.push({ text: 'Missing Content-Security-Policy header', severity: 'LOW', fix: 'Define a Content-Security-Policy for the site.' });
        } else {
            const weak = unsafeCsp(csp);
            if (weak.length > 0) {
                issues.push({
                    text: `Content-Security-Policy is weakened by ${weak.join(', ')}`,
                    severity: 'LOW',
                    fix: 'Remove unsafe-inline and unsafe-eval from script-src (use nonces or hashes) and avoid wildcard or http: sources.',
                });
            }
        }

        const xfo = (headers.get('x-frame-options') || '').trim();
        const hasAncestors = /frame-ancestors/i.test(csp);
        if (!xfo && !hasAncestors) {
            issues.push({ text: 'Missing clickjacking protection (X-Frame-Options or frame-ancestors)', severity: 'LOW', fix: 'Set X-Frame-Options or a frame-ancestors policy to prevent framing.' });
        } else if (xfo && !hasAncestors && !/^(deny|sameorigin)$/i.test(xfo)) {
            issues.push({
                text: `X-Frame-Options is "${xfo.slice(0, 40)}", which browsers ignore`,
                severity: 'LOW',
                fix: 'Set X-Frame-Options to DENY or SAMEORIGIN, or use a frame-ancestors policy.',
            });
        }
    }
    return issues;
}

/** Returns the risky parts of a policy, or nothing if it looks sound. */
export function unsafeCsp(policy: string): string[] {
    const directives = new Map<string, string[]>();
    for (const part of policy.split(';')) {
        const [name, ...values] = part.trim().split(/\s+/);
        if (name) directives.set(name.toLowerCase(), values.map((v) => v.toLowerCase()));
    }
    const scripts = directives.get('script-src') ?? directives.get('default-src');
    if (!scripts) return [];

    const found: string[] = [];
    // unsafe-inline is ignored by browsers when a nonce or hash is present.
    const hasNonce = scripts.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"));
    if (scripts.includes("'unsafe-inline'") && !hasNonce) found.push("'unsafe-inline'");
    if (scripts.includes("'unsafe-eval'")) found.push("'unsafe-eval'");
    if (scripts.some((v) => v === '*' || v === 'http:' || v === 'https:' || v === 'data:')) found.push('a wildcard script source');
    return found;
}

/** Session cookies without HttpOnly can be read by injected scripts. */
export function cookieIssues(setCookies: string[], protocol: 'http' | 'https'): HeaderIssue[] {
    const noHttpOnly: string[] = [];
    const noSecure: string[] = [];
    for (const raw of setCookies) {
        const [pair, ...attrs] = raw.split(';');
        const name = pair.split('=')[0].trim();
        if (!name) continue;
        const flags = attrs.map((a) => a.trim().toLowerCase().split('=')[0]);
        if (!flags.includes('httponly')) noHttpOnly.push(name);
        if (protocol === 'https' && !flags.includes('secure')) noSecure.push(name);
    }
    const list = (names: string[]) => Array.from(new Set(names)).slice(0, 5).join(', ');
    const issues: HeaderIssue[] = [];
    if (noHttpOnly.length > 0) {
        issues.push({ text: `Cookies set without HttpOnly (${list(noHttpOnly)})`, severity: 'LOW', fix: 'Add the HttpOnly flag to session and authentication cookies.' });
    }
    if (noSecure.length > 0) {
        issues.push({ text: `Cookies set without Secure (${list(noSecure)})`, severity: 'LOW', fix: 'Add the Secure flag so cookies are never sent over plain HTTP.' });
    }
    return issues;
}

/**
 * Certificate lifetime check. Expired is HIGH and under 30 days is MEDIUM, as
 * before. A certificate past 80% of its lifetime is noted as LOW so renewals
 * can be planned.
 */
export function certificateLifetimeIssues(validFrom: string, validTo: string, now = Date.now()): HeaderIssue[] {
    const end = new Date(validTo).getTime();
    if (Number.isNaN(end)) return [];
    const days = Math.floor((end - now) / 86_400_000);
    if (days < 0) return [{ text: 'TLS certificate has expired', severity: 'HIGH', fix: 'Renew the TLS certificate.' }];
    if (days < 30) return [{ text: `TLS certificate expires in ${days} days`, severity: 'MEDIUM', fix: 'Renew the TLS certificate before it expires.' }];

    const start = new Date(validFrom).getTime();
    if (Number.isNaN(start) || end <= start) return [];
    const left = (end - now) / (end - start);
    if (left < 0.2) {
        return [{
            text: `TLS certificate has ${Math.round(left * 100)}% of its validity left (${days} days)`,
            severity: 'LOW',
            fix: 'Schedule the renewal, or automate it so certificates are replaced well before they expire.',
        }];
    }
    return [];
}
