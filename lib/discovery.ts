import dns from 'dns';
import { askClaude, hasClaudeKey } from './ai/client';

/**
 * Enumeration helpers used when a domain is scanned. Each one mirrors a step an
 * outside attacker takes to map an organisation from nothing but its domain
 * name. All of them are passive lookups against public sources or plain DNS
 * queries, and all of them fail soft: a source that is down or blocked simply
 * contributes nothing.
 */

const dnsPromises = dns.promises;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

export const MAX_CT_NAMES = 500;
export const MAX_PATTERN_CANDIDATES = 400;
export const MAX_AI_CANDIDATES = 60;

/** Runs `worker` over `items` with a fixed number in flight at once. */
export async function pool<T>(items: T[], size: number, worker: (item: T) => Promise<void>): Promise<void> {
    let next = 0;
    const run = async () => {
        while (next < items.length) {
            const item = items[next++];
            await worker(item).catch(() => { });
        }
    };
    await Promise.all(Array.from({ length: Math.min(size, items.length) }, run));
}

async function fetchJson(url: string, timeoutMs: number): Promise<unknown> {
    const res = await fetch(url, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { accept: 'application/json', 'user-agent': 'mini-asm' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

function normaliseName(raw: string): string {
    return raw.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
}

/**
 * Certificate transparency: every publicly trusted certificate is logged, so
 * the logs list hostnames the organisation has ever requested a certificate
 * for. Returns names under `domain`, or an empty list if no log could be read.
 */
export async function certificateLogNames(domain: string): Promise<{ names: string[]; source: string | null }> {
    const inScope = (h: string) => h.endsWith(`.${domain}`) && HOST_RE.test(h);
    const collect = (raw: string[]) => Array.from(new Set(raw.map(normaliseName).filter(inScope))).slice(0, MAX_CT_NAMES);

    try {
        const rows = await fetchJson(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, 15_000) as { name_value?: string }[];
        const names = collect(rows.flatMap((r) => (r.name_value || '').split('\n')));
        if (names.length > 0) return { names, source: 'crt.sh' };
    } catch {
        // Fall through to the second log search.
    }

    try {
        const rows = await fetchJson(
            `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
            15_000,
        ) as { dns_names?: string[] }[];
        const names = collect(rows.flatMap((r) => r.dns_names || []));
        if (names.length > 0) return { names, source: 'Cert Spotter' };
    } catch {
        // Neither source answered.
    }
    return { names: [], source: null };
}

const ENV_TOKENS = ['dev', 'uat', 'test', 'qa', 'staging', 'stage', 'preprod', 'prod', 'dr', 'sit', 'sandbox'];
const CHILD_PREFIXES = ['www', 'api', 'dev', 'uat', 'test', 'staging', 'admin', 'internal', 'vpn', 'portal', 'auth', 'sso'];

/**
 * Guesses further names from the ones already found. Organisations name hosts
 * to a pattern, so `api-uat` suggests `api-dev` and `api-prod`, `web1` suggests
 * `web2`, and a found `api.example.com` may have `dev.api.example.com` below it.
 */
export function patternCandidates(domain: string, found: string[]): string[] {
    const out = new Set<string>();
    const known = new Set(found);
    const add = (host: string) => {
        if (!known.has(host) && host.length <= 253 && HOST_RE.test(host)) out.add(host);
    };

    const labels = new Set<string>();
    for (const host of found) {
        if (!host.endsWith(`.${domain}`)) continue;
        const prefix = host.slice(0, -domain.length - 1);
        labels.add(prefix);
    }

    for (const label of labels) {
        const first = label.split('.')[0];
        const rest = label.includes('.') ? label.slice(first.length) : '';
        const variant = (l: string) => add(`${l}${rest}.${domain}`);

        // Swap or add an environment token: api-uat -> api-dev, api -> api-dev, dev-api.
        const parts = first.split('-');
        const envIndex = parts.findIndex((p) => ENV_TOKENS.includes(p));
        for (const env of ENV_TOKENS) {
            if (envIndex >= 0) {
                const swapped = [...parts];
                swapped[envIndex] = env;
                variant(swapped.join('-'));
            } else if (!ENV_TOKENS.includes(first)) {
                variant(`${first}-${env}`);
                variant(`${env}-${first}`);
            }
        }
        if (envIndex >= 0 && parts.length > 1) variant(parts.filter((_, i) => i !== envIndex).join('-'));

        // Numbered hosts: web1 -> web2, web3; mail -> mail1, mail2.
        const numbered = first.match(/^(.*?)(\d{1,2})$/);
        if (numbered) {
            const n = parseInt(numbered[2], 10);
            for (const m of [n - 1, n + 1, n + 2]) if (m >= 0) variant(`${numbered[1]}${m}`);
        } else {
            variant(`${first}1`);
            variant(`${first}2`);
        }
    }

    // One level down from every found host.
    for (const host of found.slice(0, 25)) {
        for (const child of CHILD_PREFIXES) add(`${child}.${host}`);
    }

    return Array.from(out).slice(0, MAX_PATTERN_CANDIDATES);
}

/**
 * Asks the model for likely sibling hostnames given the naming pattern seen so
 * far. Only used when an API key is configured. Returns full hostnames.
 */
export async function aiCandidates(domain: string, found: string[]): Promise<string[]> {
    if (!hasClaudeKey() || found.length === 0) return [];

    const system = 'You help a security team map their own external attack surface. '
        + 'Given hostnames already discovered under a domain the team owns, propose further hostnames that are likely to exist, '
        + 'based on the naming conventions you can see (environments, regions, numbering, product names, abbreviations). '
        + `Reply with a JSON array of at most ${MAX_AI_CANDIDATES} strings and nothing else. Each string is the part before the domain, for example "api-dr" or "dev.portal".`;
    const user = `Domain: ${domain}\nKnown hostnames:\n${found.slice(0, 150).join('\n')}`;

    const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 20_000));
    const result = await Promise.race([askClaude(system, user, 1200), timeout]);
    if (!result || !result.ok || !result.text) return [];

    const match = result.text.match(/\[[\s\S]*\]/);
    if (!match) return [];
    try {
        const parsed: unknown = JSON.parse(match[0]);
        if (!Array.isArray(parsed)) return [];
        const known = new Set(found);
        const hosts = parsed
            .filter((v): v is string => typeof v === 'string')
            .map((v) => v.trim().toLowerCase().replace(new RegExp(`\\.?${domain.replace(/\./g, '\\.')}$`), ''))
            .filter((v) => v.length > 0 && v.length <= 80 && v.split('.').every((l) => LABEL_RE.test(l)))
            .map((v) => `${v}.${domain}`)
            .filter((h) => !known.has(h));
        return Array.from(new Set(hosts)).slice(0, MAX_AI_CANDIDATES);
    } catch {
        return [];
    }
}

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'mil', 'nom', 'web', 'law', 'school']);

/** Approximate registrable domain: example.co.za for a.b.example.co.za. */
export function registrableDomain(host: string): string {
    const parts = host.toLowerCase().replace(/\.$/, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    const take = tld.length === 2 && SECOND_LEVEL.has(sld) ? 3 : 2;
    return parts.slice(-take).join('.');
}

const PROVIDERS: [RegExp, string][] = [
    [/\.cloudfront\.net$/, 'AWS CloudFront'],
    [/\.elb\.amazonaws\.com$/, 'AWS load balancer'],
    [/\.s3[.-][a-z0-9.-]*amazonaws\.com$/, 'AWS S3'],
    [/\.amazonaws\.com$/, 'AWS'],
    [/\.azurewebsites\.net$/, 'Azure App Service'],
    [/\.trafficmanager\.net$/, 'Azure Traffic Manager'],
    [/\.azureedge\.net$|\.azurefd\.net$/, 'Azure Front Door / CDN'],
    [/\.cloudapp\.azure\.com$|\.cloudapp\.net$/, 'Azure virtual machine'],
    [/\.windows\.net$/, 'Azure storage'],
    [/\.outlook\.com$|\.office\.com$|\.office365\.com$|\.lync\.com$/, 'Microsoft 365'],
    [/\.googlehosted\.com$|^ghs\.google\.com$|\.googleusercontent\.com$/, 'Google'],
    [/\.github\.io$/, 'GitHub Pages'],
    [/\.herokuapp\.com$|\.herokudns\.com$/, 'Heroku'],
    [/\.fastly\.net$/, 'Fastly'],
    [/\.cloudflare\.net$|\.cdn\.cloudflare\.net$/, 'Cloudflare'],
    [/\.edgekey\.net$|\.akamaiedge\.net$|\.edgesuite\.net$/, 'Akamai'],
    [/\.incapdns\.net$/, 'Imperva'],
    [/\.netlify\.app$|\.netlify\.com$/, 'Netlify'],
    [/\.vercel-dns\.com$|\.vercel\.app$/, 'Vercel'],
    [/\.zendesk\.com$/, 'Zendesk'],
    [/\.freshdesk\.com$/, 'Freshdesk'],
    [/\.force\.com$|\.salesforce\.com$/, 'Salesforce'],
    [/\.hubspot\.net$|\.hs-sites\.com$/, 'HubSpot'],
    [/\.myshopify\.com$/, 'Shopify'],
    [/\.wpengine\.com$/, 'WP Engine'],
    [/\.atlassian\.net$|\.atlassian\.com$/, 'Atlassian'],
    [/\.mimecast\.com$|\.mimecast\.co\.za$/, 'Mimecast'],
    [/\.pphosted\.com$/, 'Proofpoint'],
];

export function providerFor(host: string): string | null {
    const h = host.toLowerCase().replace(/\.$/, '');
    for (const [re, name] of PROVIDERS) if (re.test(h)) return name;
    return null;
}

/** Follows the alias chain for a hostname. Returns the targets in order, without the starting name. */
export async function cnameChain(host: string): Promise<string[]> {
    const chain: string[] = [];
    let current = host;
    for (let i = 0; i < 6; i++) {
        const next = await dnsPromises.resolveCname(current).catch(() => [] as string[]);
        if (next.length === 0) break;
        current = next[0].toLowerCase().replace(/\.$/, '');
        if (chain.includes(current)) break;
        chain.push(current);
    }
    return chain;
}

const TXT_SERVICES: [RegExp, string][] = [
    [/^google-site-verification=/i, 'Google Workspace / Search Console'],
    [/^ms=ms\d+/i, 'Microsoft 365'],
    [/^atlassian-domain-verification=/i, 'Atlassian'],
    [/^facebook-domain-verification=/i, 'Meta Business'],
    [/^docusign=/i, 'DocuSign'],
    [/^apple-domain-verification=/i, 'Apple'],
    [/^adobe-idp-site-verification=/i, 'Adobe'],
    [/^zoom[-_]?(domain-)?verif/i, 'Zoom'],
    [/^stripe-verification=/i, 'Stripe'],
    [/^amazonses:/i, 'Amazon SES'],
    [/^globalsign-domain-verification=/i, 'GlobalSign'],
    [/^_?globalsign/i, 'GlobalSign'],
    [/^miro-verification=/i, 'Miro'],
    [/^cisco-ci-domain-verification=/i, 'Cisco Webex'],
    [/^mongodb-site-verification=/i, 'MongoDB Atlas'],
    [/^slack-domain-verification=/i, 'Slack'],
    [/^hubspot-developer-verification=/i, 'HubSpot'],
    [/^zoho-verification=/i, 'Zoho'],
    [/^pardot/i, 'Salesforce Pardot'],
    [/^onetrust-domain-verification=/i, 'OneTrust'],
    [/^have-i-been-pwned-verification=/i, 'Have I Been Pwned'],
    [/^openai-domain-verification=/i, 'OpenAI'],
    [/^anthropic-domain-verification/i, 'Anthropic'],
    [/^knowbe4-site-verification=/i, 'KnowBe4'],
    [/^mimecast/i, 'Mimecast'],
    [/^teamviewer-sso-verification=/i, 'TeamViewer'],
    [/^dropbox-domain-verification=/i, 'Dropbox'],
    [/^citrix-verification-code=/i, 'Citrix'],
    [/^fortifi-domain-verification=|^fortinet/i, 'Fortinet'],
];

/** Third-party services revealed by domain verification TXT records. */
export function servicesFromTxt(records: string[]): string[] {
    const out = new Set<string>();
    for (const record of records) {
        for (const [re, name] of TXT_SERVICES) if (re.test(record.trim())) out.add(name);
    }
    return Array.from(out);
}

/** Pulls the declared sending infrastructure out of an SPF record. */
export function parseSpf(record: string): { includes: string[]; ranges: string[] } {
    const includes: string[] = [];
    const ranges: string[] = [];
    for (const term of record.split(/\s+/)) {
        const t = term.replace(/^[+~?-]/, '').toLowerCase();
        if (t.startsWith('include:')) includes.push(t.slice(8));
        else if (t.startsWith('redirect=')) includes.push(t.slice(9));
        else if (t.startsWith('ip4:')) ranges.push(t.slice(4));
        else if (t.startsWith('ip6:')) ranges.push(t.slice(4));
    }
    return { includes, ranges };
}

const SRV_NAMES = [
    '_sip._tls', '_sips._tcp', '_sipfederationtls._tcp', '_autodiscover._tcp', '_ldap._tcp', '_ldaps._tcp',
    '_kerberos._tcp', '_kerberos._udp', '_xmpp-server._tcp', '_xmpp-client._tcp', '_imaps._tcp', '_submission._tcp',
    '_caldavs._tcp', '_carddavs._tcp', '_h323cs._tcp', '_vlmcs._tcp', '_gc._tcp',
];

/** Service records advertise where chat, directory and mail client services live. */
export async function srvRecords(domain: string): Promise<{ name: string; target: string; port: number }[]> {
    const out: { name: string; target: string; port: number }[] = [];
    await pool(SRV_NAMES, 10, async (name) => {
        const records = await dnsPromises.resolveSrv(`${name}.${domain}`).catch(() => [] as dns.SrvRecord[]);
        for (const r of records) {
            const target = r.name.toLowerCase().replace(/\.$/, '');
            if (target) out.push({ name, target, port: r.port });
        }
    });
    return out;
}

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 's1', 's2', 'dkim', 'mimecast', 'smtp', 'mandrill', 'sendgrid'];

/** DKIM selectors that exist for the domain. A selector name often identifies the mail platform. */
export async function dkimSelectors(domain: string): Promise<string[]> {
    const found: string[] = [];
    await pool(DKIM_SELECTORS, 10, async (selector) => {
        const name = `${selector}._domainkey.${domain}`;
        const txt = await dnsPromises.resolveTxt(name).catch(() => [] as string[][]);
        const cname = txt.length === 0 ? await dnsPromises.resolveCname(name).catch(() => [] as string[]) : [];
        if (txt.length > 0 || cname.length > 0) found.push(selector);
    });
    return found.sort();
}

export interface NetworkOwner {
    name: string;
    range: string;
    country: string;
}

/**
 * Registry lookup for who an address block is assigned to. This is how an
 * attacker tells an organisation's own network apart from a shared cloud or
 * CDN, and how they learn the size of the block around a known address.
 */
export async function networkOwner(ip: string): Promise<NetworkOwner | null> {
    try {
        const data = await fetchJson(`https://rdap.org/ip/${ip}`, 8_000) as {
            name?: string;
            country?: string;
            startAddress?: string;
            endAddress?: string;
            cidr0_cidrs?: { v4prefix?: string; length?: number }[];
            entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, string][]] }[];
        };

        let org = '';
        for (const entity of data.entities || []) {
            if (!entity.roles?.some((r) => r === 'registrant' || r === 'administrative')) continue;
            const fn = entity.vcardArray?.[1]?.find((f) => f[0] === 'fn');
            if (fn && typeof fn[3] === 'string') {
                org = fn[3];
                break;
            }
        }

        const cidr = data.cidr0_cidrs?.[0];
        const range = cidr?.v4prefix ? `${cidr.v4prefix}/${cidr.length}` : [data.startAddress, data.endAddress].filter(Boolean).join(' to ');
        const name = [org, data.name].filter(Boolean).join(' / ');
        if (!name && !range) return null;
        return { name: name.slice(0, 120) || 'unknown', range, country: data.country || '' };
    } catch {
        return null;
    }
}
