/**
 * Works out which threat scenarios make sense for one asset picked from the
 * attack surface, based on what the scan already found on it. Pure data in,
 * data out, so the attack surface page and the tests can both use it.
 */

export interface AssetPort {
    port: number;
    protocol?: string;
    service?: string | null;
}

export interface Asset {
    /** The IP address or hostname that will be tested. */
    target: string;
    ports: AssetPort[];
}

export interface Suggestion {
    scenarioId: string;
    /** Why it applies to this asset, in a few words. */
    reason: string;
}

const WEB_PORTS = new Set([80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9443]);
const TLS_PORTS = new Set([443, 465, 636, 853, 989, 990, 993, 995, 5986, 8443, 9443]);
// Data stores and admin APIs that proof-of-reach, proof-of-command and proof-of-data know how to handle.
const DATA_PORTS = new Set([2375, 2376, 5984, 6379, 9200, 9300, 11211, 27017, 27018]);
const COMMAND_PORTS = new Set([2375, 2376, 6379, 9200]);
const SENSITIVE_PORTS = new Set([
    21, 22, 23, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, ...DATA_PORTS,
]);

export const isIp = (target: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(target) || target.includes(':');

const isWeb = (p: AssetPort) => WEB_PORTS.has(p.port) || /http|web/i.test(p.service ?? '');
const isTls = (p: AssetPort) => TLS_PORTS.has(p.port) || /https|ssl|tls/i.test(p.service ?? '');

const list = (ports: number[]) => ports.slice(0, 4).join(', ') + (ports.length > 4 ? '…' : '');

export function suggestScenarios(input: Asset): Suggestion[] {
    // The scenarios connect over TCP, so UDP findings such as NTP or SNMP do not qualify a target.
    const asset = { ...input, ports: input.ports.filter((p) => (p.protocol ?? 'tcp') === 'tcp') };
    const out: Suggestion[] = [];
    const add = (scenarioId: string, reason: string) => {
        if (!out.some((s) => s.scenarioId === scenarioId)) out.push({ scenarioId, reason });
    };

    const web = asset.ports.filter(isWeb).map((p) => p.port);
    const tls = asset.ports.filter(isTls).map((p) => p.port);
    const sensitive = asset.ports.filter((p) => SENSITIVE_PORTS.has(p.port)).map((p) => p.port);
    const data = asset.ports.filter((p) => DATA_PORTS.has(p.port)).map((p) => p.port);
    const command = asset.ports.filter((p) => COMMAND_PORTS.has(p.port)).map((p) => p.port);
    const domain = !isIp(asset.target);

    add('recon-exposure', 'Refreshes the open ports and services');
    if (asset.ports.length > 0) add('cve-enrichment', 'Matches service versions to known CVEs');
    add('exposed-services', sensitive.length ? `Sensitive services open (${list(sensitive)})` : 'Checks for leaked files and admin services');

    if (web.length) {
        const on = `Web on ${list(web)}`;
        add('web-tech-vulns', `${on}: version checks against known vulnerabilities`);
        add('web-exposure-scan', `${on}: confirms exposed files without reading them`);
        add('security-headers', on);
        add('cookie-security', on);
        add('cors-misconfig', on);
        add('http-methods', on);
        add('directory-listing', on);
        add('open-redirect', on);
    }
    if (tls.length) add('tls-posture', `TLS on ${list(tls)}`);

    if (domain) {
        add('subdomain-takeover', 'Hostname may point at an unclaimed cloud resource');
        add('email-posture', 'SPF and DMARC for the domain');
    }

    // Active proofs: still non-destructive, but only run on an authorised ACTIVE engagement.
    if (web.length) add('waf-detect-bypass', `Web on ${list(web)}: is there a WAF, and can the origin be reached around it`);
    if (sensitive.length) add('proof-of-reach', `Proves a connection to ${list(sensitive)}`);
    if (command.length) add('proof-of-command', `Read-only command on ${list(command)}`);
    if (data.length) add('proof-of-data', `Metadata only from ${list(data)}`);

    return out;
}
