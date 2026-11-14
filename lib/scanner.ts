import net from 'net';
import tls from 'tls';
import dns from 'dns';
import { randomBytes } from 'crypto';
import { isScannableIp, parseTarget, MAX_IPS_PER_SCAN } from './targets';
import {
    aiCandidates, certificateLogNames, cnameChain, dkimSelectors, networkOwner, parseSpf, patternCandidates, pool,
    providerFor, registrableDomain, servicesFromTxt, srvRecords,
} from './discovery';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ScanResult {
    ip: string;
    port: number;
    service: string;
    version?: string;
    banner?: string;
    severity: Severity;
    description: string;
    vulnerability?: string;
    remediation?: string;
    forensics?: string;
    upstreamVersion?: string;
    domains?: string;
    techStack?: string;
}

const COMMON_PORTS: Record<number, { service: string; severity: Severity; description: string }> = {
    21: { service: 'FTP', severity: 'HIGH', description: 'File Transfer Protocol - often insecure' },
    22: { service: 'SSH', severity: 'LOW', description: 'Secure Shell Management' },
    23: { service: 'Telnet', severity: 'CRITICAL', description: 'Telnet - Insecure clear-text management' },
    25: { service: 'SMTP', severity: 'MEDIUM', description: 'Email Transfer' },
    53: { service: 'DNS', severity: 'LOW', description: 'Domain Name System' },
    80: { service: 'HTTP', severity: 'INFO', description: 'Web Server (Cleartext)' },
    110: { service: 'POP3', severity: 'MEDIUM', description: 'Post Office Protocol' },
    111: { service: 'RPCBind', severity: 'HIGH', description: 'Portmapper - often used in NFS/RPC attacks' },
    135: { service: 'RPC', severity: 'MEDIUM', description: 'Microsoft RPC Endpoint Mapper' },
    139: { service: 'NetBIOS', severity: 'HIGH', description: 'NetBIOS Session Service' },
    143: { service: 'IMAP', severity: 'MEDIUM', description: 'Internet Message Access Protocol' },
    389: { service: 'LDAP', severity: 'HIGH', description: 'Lightweight Directory Access Protocol' },
    443: { service: 'HTTPS', severity: 'INFO', description: 'Secure Web Server' },
    445: { service: 'SMB', severity: 'HIGH', description: 'Microsoft-DS - high risk for lateral movement' },
    465: { service: 'SMTPS', severity: 'LOW', description: 'Secure SMTP' },
    500: { service: 'IKE', severity: 'LOW', description: 'ISAKMP / VPN Key Exchange' },
    587: { service: 'Submission', severity: 'LOW', description: 'Email Submission Port' },
    636: { service: 'LDAPS', severity: 'LOW', description: 'Secure LDAP' },
    993: { service: 'IMAPS', severity: 'LOW', description: 'Secure IMAP' },
    995: { service: 'POP3S', severity: 'LOW', description: 'Secure POP3' },
    1194: { service: 'OpenVPN', severity: 'LOW', description: 'OpenVPN Service' },
    1433: { service: 'MSSQL', severity: 'HIGH', description: 'Microsoft SQL Server' },
    1521: { service: 'Oracle', severity: 'HIGH', description: 'Oracle Database' },
    1723: { service: 'PPTP', severity: 'MEDIUM', description: 'Point-to-Point Tunneling Protocol' },
    2049: { service: 'NFS', severity: 'HIGH', description: 'Network File System' },
    2222: { service: 'SSH-Alt', severity: 'LOW', description: 'Alternative SSH Port' },
    2375: { service: 'Docker', severity: 'CRITICAL', description: 'Docker Daemon (Unencrypted)' },
    2376: { service: 'Docker-TLS', severity: 'HIGH', description: 'Docker Daemon (TLS)' },
    3000: { service: 'Dev-Web', severity: 'INFO', description: 'Common development web port' },
    3306: { service: 'MySQL', severity: 'HIGH', description: 'MySQL Database' },
    3389: { service: 'RDP', severity: 'HIGH', description: 'Remote Desktop Protocol' },
    4443: { service: 'VPN-Web', severity: 'LOW', description: 'Common VPN Web Interface' },
    4500: { service: 'NAT-T', severity: 'LOW', description: 'IPsec NAT Traversal' },
    5060: { service: 'SIP', severity: 'LOW', description: 'Session Initiation Protocol (VOIP)' },
    5432: { service: 'PostgreSQL', severity: 'HIGH', description: 'PostgreSQL Database' },
    5900: { service: 'VNC', severity: 'HIGH', description: 'Virtual Network Computing' },
    5985: { service: 'WinRM-HTTP', severity: 'MEDIUM', description: 'Windows Remote Management' },
    5986: { service: 'WinRM-HTTPS', severity: 'LOW', description: 'Windows Remote Management (Secure)' },
    6379: { service: 'Redis', severity: 'HIGH', description: 'Redis Key-Value Store' },
    6443: { service: 'K8s-API', severity: 'HIGH', description: 'Kubernetes API Server' },
    8000: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative Web Port' },
    8080: { service: 'HTTP-Proxy', severity: 'INFO', description: 'Web Proxy / Alternative Port' },
    8443: { service: 'HTTPS-Alt', severity: 'INFO', description: 'Alternative Secure Web Port' },
    8888: { service: 'HTTP-Dev', severity: 'INFO', description: 'Development/Jupyter Web Port' },
    9000: { service: 'SonarQube/Web', severity: 'INFO', description: 'Common tool/web port' },
    9200: { service: 'Elasticsearch', severity: 'HIGH', description: 'Elasticsearch API' },
    9443: { service: 'VSphere', severity: 'HIGH', description: 'VMware vSphere Web Client' },
    10250: { service: 'Kubelet', severity: 'HIGH', description: 'Kubernetes Kubelet API' },
    11211: { service: 'Memcached', severity: 'HIGH', description: 'Memcached Cache' },
    27017: { service: 'MongoDB', severity: 'HIGH', description: 'MongoDB Database' },
};

const dnsPromises = dns.promises;

const SEVERITY_RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function maxSeverity(...levels: Severity[]): Severity {
    return levels.reduce((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a), 'INFO' as Severity);
}

const WEB_PORTS = new Set([80, 443, 3000, 8000, 8080, 8443, 8888]);
const TLS_PORTS = new Set([443, 8443]);
const MAX_BODY_BYTES = 256 * 1024;
const MAX_BANNER_BYTES = 512;

/** Strip control characters so remote data is safe to store and render. */
function clean(text: string, max = 200): string {
    return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);
}

interface Issue {
    text: string;
    severity: Severity;
    /** What to do about it. Shown as the recommended action. */
    fix?: string;
}

interface WebDetails {
    reached: boolean;
    title: string;
    server: string;
    tech: string[];
    issues: Issue[];
}

async function readBody(response: Response): Promise<string> {
    if (!response.body) return '';
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let received = 0;
    try {
        while (received < MAX_BODY_BYTES) {
            const { done, value } = await reader.read();
            if (done) break;
            received += value.byteLength;
            text += decoder.decode(value, { stream: true });
        }
    } finally {
        reader.cancel().catch(() => { });
    }
    return text;
}

async function fetchWebDetails(ip: string, port: number, hostname?: string): Promise<WebDetails> {
    const details: WebDetails = { reached: false, title: '', server: '', tech: [], issues: [] };
    const protocol = TLS_PORTS.has(port) ? 'https' : 'http';
    // Prefer the hostname so virtual hosts and CDNs return the real site.
    const url = `${protocol}://${hostname || ip}:${port}/`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        // Redirects are not followed: the probe must stay on the host being scanned.
        const response = await fetch(url, { signal: controller.signal, redirect: 'manual' });
        details.reached = true;
        details.server = clean(response.headers.get('server') || '', 80);
        const poweredBy = clean(response.headers.get('x-powered-by') || '', 80);
        const body = await readBody(response);
        const lower = body.toLowerCase();

        const titleMatch = body.match(/<title[^>]*>([^<]{0,300})<\/title>/i);
        details.title = titleMatch ? clean(titleMatch[1], 120) : '';

        if (poweredBy) details.tech.push(`Backend: ${poweredBy}`);
        if (lower.includes('wp-content')) details.tech.push('CMS: WordPress');
        if (lower.includes('_next/static')) details.tech.push('Framework: Next.js');
        if (lower.includes('laravel')) details.tech.push('Framework: Laravel');
        if (lower.includes('csrfmiddlewaretoken')) details.tech.push('Framework: Django');
        const serverLower = details.server.toLowerCase();
        if (serverLower.includes('apache')) details.tech.push('Server: Apache');
        if (serverLower.includes('nginx')) details.tech.push('Server: Nginx');
        if (serverLower.includes('microsoft-iis')) details.tech.push('Server: IIS');
        if (serverLower.includes('cloudflare')) details.tech.push('Proxy: Cloudflare');

        const isRedirect = response.status >= 300 && response.status < 400;
        const location = response.headers.get('location') || '';
        if (protocol === 'http') {
            if (!(isRedirect && location.startsWith('https://'))) {
                details.issues.push({ text: 'Content served over unencrypted HTTP', severity: 'LOW', fix: 'Redirect all HTTP traffic to HTTPS.' });
            }
        } else if (!response.headers.get('strict-transport-security')) {
            details.issues.push({ text: 'Missing Strict-Transport-Security header', severity: 'LOW', fix: 'Send a Strict-Transport-Security header so browsers always use HTTPS.' });
        }
        if (!isRedirect) {
            const csp = response.headers.get('content-security-policy') || '';
            if (!csp) details.issues.push({ text: 'Missing Content-Security-Policy header', severity: 'LOW', fix: 'Define a Content-Security-Policy for the site.' });
            if (!response.headers.get('x-frame-options') && !csp.includes('frame-ancestors')) {
                details.issues.push({ text: 'Missing clickjacking protection (X-Frame-Options or frame-ancestors)', severity: 'LOW', fix: 'Set X-Frame-Options or a frame-ancestors policy to prevent framing.' });
            }
        }
    } catch {
        // Unreachable, TLS failure or timeout: nothing to report.
    } finally {
        clearTimeout(timer);
    }
    return details;
}

interface SSLInfo {
    issuer: string;
    validTo: string;
    sans: string[];
    issues: Issue[];
}

// Certificate analysis. SANs are also used for subdomain discovery.
function extractSSLInfo(host: string, port = 443, servername?: string): Promise<SSLInfo> {
    return new Promise((resolve) => {
        const result: SSLInfo = { issuer: '', validTo: '', sans: [], issues: [] };
        let settled = false;
        const finish = () => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(result);
        };

        // Verification is disabled on purpose: the goal is to inspect whatever
        // certificate is presented, including invalid ones. Nothing is sent.
        const socket = tls.connect({
            host,
            port,
            servername: servername && !net.isIP(servername) ? servername : undefined,
            timeout: 5000,
            rejectUnauthorized: false,
        }, () => {
            try {
                const cert = socket.getPeerCertificate();
                if (cert && cert.valid_to) {
                    const issuer = cert.issuer?.O || cert.issuer?.CN || '';
                    result.issuer = clean(Array.isArray(issuer) ? issuer.join(' ') : issuer, 100);
                    result.validTo = cert.valid_to;

                    const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
                    if (days < 0) {
                        result.issues.push({ text: 'TLS certificate has expired', severity: 'HIGH', fix: 'Renew the TLS certificate.' });
                    } else if (days < 30) {
                        result.issues.push({ text: `TLS certificate expires in ${days} days`, severity: 'MEDIUM', fix: 'Renew the TLS certificate before it expires.' });
                    }

                    if (servername && !socket.authorized && days >= 0) {
                        const reason = clean(String(socket.authorizationError || 'unknown reason'), 80);
                        result.issues.push({ text: `TLS certificate is not trusted (${reason})`, severity: 'MEDIUM', fix: 'Install a certificate from a trusted authority that matches the hostname.' });
                    }

                    if (cert.subjectaltname) {
                        result.sans = cert.subjectaltname
                            .split(', ')
                            .filter((s) => s.startsWith('DNS:'))
                            .map((s) => s.slice(4).trim().toLowerCase())
                            .filter((s) => s && !s.includes('*'));
                    }
                }
            } catch {
                // Malformed certificate data: report what we have.
            }
            finish();
        });

        socket.on('error', finish);
        socket.on('timeout', finish);
    });
}

function extractVersion(banner: string | null): string | undefined {
    if (!banner) return undefined;
    // Ignore protocol versions like SSH-2.0 or HTTP/1.1
    const stripped = banner.replace(/^SSH-\d+\.\d+-/i, '').replace(/HTTP\/\d\.\d/gi, '');
    const match = stripped.match(/\d+\.\d+(\.\d+)?/);
    return match ? match[0] : undefined;
}

interface Assessment {
    issues: Issue[];
    forensics: string[];
    upstreamVersion?: string;
}

function assessService(service: string, port: number, fingerprint: string, version?: string): Assessment {
    const issues: Issue[] = [];
    const forensics: string[] = [`Port ${port} (${service}) accepted a TCP connection`];
    let upstreamVersion: string | undefined;
    const f = fingerprint.toLowerCase();

    if (version) forensics.push(`Version string identified: ${version}`);

    if (/microsoft-iis\/(6\.0|7\.0|7\.5|8\.0|8\.5)/.test(f)) {
        issues.push({ text: 'Legacy IIS version on an unsupported Windows Server release', severity: 'MEDIUM', fix: 'Migrate to a supported Windows Server release running IIS 10.' });
        forensics.push('Logic: Server header matches an end-of-life IIS version.');
    }

    const openssh = f.match(/openssh[_-](\d+\.\d+)/);
    if (openssh && parseFloat(openssh[1]) < 8.9) {
        issues.push({ text: `OpenSSH ${openssh[1]} is older than the 8.9 baseline`, severity: 'MEDIUM', fix: 'Confirm the distribution has backported security fixes, or upgrade OpenSSH to a current release.' });
        forensics.push(`Logic: OpenSSH ${openssh[1]} < 8.9. Distributions often backport fixes, so verify on the host.`);
    }

    if (/apache\/2\.4\.(49|50)\b/.test(f)) {
        upstreamVersion = '2.4.51+';
        issues.push({ text: 'CVE-2021-41773 / CVE-2021-42013: Apache path traversal and remote code execution', severity: 'CRITICAL', fix: 'Upgrade Apache HTTP Server to 2.4.51 or later immediately. These versions are actively exploited.' });
        forensics.push('Logic: Server header matches Apache 2.4.49 or 2.4.50.');
    }

    if (port === 445 || port === 139) {
        issues.push({ text: 'SMB/NetBIOS reachable from the scanner', severity: 'HIGH', fix: 'Block SMB at the network edge and require SMB signing on hosts that must expose it.' });
    }

    if (port === 3389) {
        issues.push({ text: 'RDP reachable from the scanner', severity: 'HIGH', fix: 'Require Network Level Authentication and restrict RDP to VPN or a bastion host.' });
    }

    if (port === 23) {
        issues.push({ text: 'Telnet sends credentials in clear text', severity: 'CRITICAL', fix: 'Disable Telnet and use SSH for remote management.' });
    }

    if (port === 2375) {
        issues.push({ text: 'Unauthenticated Docker daemon port is reachable', severity: 'CRITICAL', fix: 'Never expose the Docker API without TLS client authentication. Firewall this port.' });
    }

    return { issues, forensics, upstreamVersion };
}

function checkPort(ip: string, port: number, timeout = 1000): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const finish = (open: boolean) => {
            socket.destroy();
            resolve(open);
        };
        socket.setTimeout(timeout);
        socket.once('error', () => finish(false));
        socket.once('timeout', () => finish(false));
        socket.connect(port, ip, () => finish(true));
    });
}

function grabBanner(ip: string, port: number, timeout = 3000): Promise<string | null> {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let resolved = false;

        const done = () => {
            if (resolved) return;
            resolved = true;
            socket.destroy();
            resolve(data ? data.slice(0, MAX_BANNER_BYTES) : null);
        };

        socket.setTimeout(timeout);
        socket.once('error', done);
        socket.once('timeout', done);
        socket.once('end', done);

        socket.connect(port, ip, () => {
            if (WEB_PORTS.has(port) && !TLS_PORTS.has(port)) {
                socket.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
            }
        });

        socket.on('data', (chunk) => {
            data += chunk.toString('latin1');
            // Server-first protocols (SSH, SMTP, FTP) send the banner in the first packet.
            if (!WEB_PORTS.has(port) || data.length >= MAX_BANNER_BYTES) done();
        });
    });
}

function guessSystem(port: number, banner: string | null): string {
    const b = banner?.toLowerCase() || '';
    if (port === 445 || port === 139) return 'Windows (SMB)';
    if (port === 3389) return 'Windows (RDP)';
    if (b.includes('ubuntu')) return 'Ubuntu Linux';
    if (b.includes('debian')) return 'Debian Linux';
    if (b.includes('centos')) return 'CentOS Linux';
    if (b.includes('apache')) return 'Apache HTTPd';
    if (b.includes('nginx')) return 'Nginx';
    if (b.includes('openssh')) return 'OpenSSH';
    if (port === 3306) return 'MySQL/MariaDB';
    if (port === 5432) return 'PostgreSQL';
    if (port === 27017) return 'MongoDB';
    if (port === 6379) return 'Redis';
    if (port === 22) return 'SSH server';
    if (port === 80 || port === 443) return 'Web server';
    return 'Unknown';
}

const COMMON_SUBDOMAINS = Array.from(new Set([
    'www', 'mail', 'vpn', 'api', 'dev', 'portal', 'remote', 'secure', 'aws', 'owa', 'mail2', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
    'autodiscover', 'staging', 'test', 'git', 'gitlab', 'm', 'admin', 'status', 'support', 'docs', 'blog', 'shop', 'cdn', 'app',
    'internal', 'cloud', 'gateway', 'ssh', 'ftp', 'sql', 'db', 'database', 'jenkins', 'jira', 'confluence', 'wiki', 'proxy',
    'webmail', 'exchange', 'office', 'mobile', 'static', 'assets', 'api-dev', 'api-staging', 'demo', 'uat', 'prod', 'production',
    'billing', 'payment', 'store', 'help', 'hr', 'hr-portal', 'staff', 'employee', 'intranet', 'extranet', 'partner',
    'client', 'customer', 'api2', 'api3', 'v2', 'v1', 'legacy', 'old', 'new', 'monitor', 'zabbix', 'nagios', 'grafana', 'prometheus',
    'kibana', 'elastic', 'docker', 'k8s', 'kubernetes', 'registry', 'vault', 'consul', 'backup', 'nas', 'storage', 'san', 'private',
    'hidden', 'secret', 'management', 'console', 'config', 'setup', 'install', 'webhook', 'hooks', 'callback', 'metrics',
]));

export interface DomainResolution {
    ips: string[];
    details: string[];
    /** IP address to the hostnames under the target domain that resolve to it. */
    hostMap: Record<string, string[]>;
    subdomains: string[];
    subdomainCount: number;
    /** Names seen in certificate logs that no longer resolve. Candidates for dangling records. */
    staleNames: string[];
    /** Other registrable domains that share certificates or infrastructure with the target. */
    relatedDomains: string[];
}

const resolve4 = (name: string) => dnsPromises.resolve4(name).catch(() => [] as string[]);
const stripDot = (h: string) => h.toLowerCase().replace(/\.$/, '');

/**
 * Maps a domain the way an outside attacker would: DNS records, certificate
 * logs, certificates presented by each host, naming patterns, alias chains and
 * address ownership. Only names under the target domain are added to the scan.
 * Anything else that turns up is reported as related but left alone.
 */
export async function resolveDomain(domain: string): Promise<DomainResolution> {
    const details: string[] = [];
    const hostMap: Record<string, string[]> = {};
    const subdomains = new Set<string>();
    const tried = new Set<string>([domain]);
    const related = new Set<string>();

    const link = (ip: string, host: string) => {
        if (!hostMap[ip]) hostMap[ip] = [];
        if (!hostMap[ip].includes(host)) hostMap[ip].push(host);
    };
    const inScope = (host: string) => host === domain || host.endsWith(`.${domain}`);
    const noteRelated = (host: string) => {
        const reg = registrableDomain(host);
        if (reg && reg !== registrableDomain(domain) && !providerFor(host)) related.add(reg);
    };

    const aRecords = await resolve4(domain);
    aRecords.forEach((ip) => link(ip, domain));
    if (aRecords.length > 0) details.push(`A Records: ${aRecords.join(', ')}`);

    const aaaa = await dnsPromises.resolve6(domain).catch(() => [] as string[]);
    if (aaaa.length > 0) details.push(`AAAA Records: ${aaaa.join(', ')} (IPv6 is recorded but not scanned)`);

    // Name servers and mail exchangers are recorded, but only scanned when they
    // sit under the target domain. They usually belong to a third-party provider
    // that the operator has no authority to probe.
    const nsRecords = (await dnsPromises.resolveNs(domain).catch(() => [] as string[])).map(stripDot);
    if (nsRecords.length > 0) details.push(`Nameservers: ${nsRecords.join(', ')}`);

    const mxRecords = await dnsPromises.resolveMx(domain).catch(() => [] as dns.MxRecord[]);
    mxRecords.forEach((mx) => {
        const provider = providerFor(mx.exchange);
        details.push(`MX Record: ${stripDot(mx.exchange)} (priority ${mx.priority})${provider ? ` [${provider}]` : ''}`);
    });

    const srv = await srvRecords(domain);
    srv.forEach((r) => details.push(`SRV Record: ${r.name} -> ${r.target}:${r.port}`));

    const infraHosts = [...nsRecords, ...mxRecords.map((mx) => stripDot(mx.exchange)), ...srv.map((r) => r.target)];
    infraHosts.filter((h) => !inScope(h)).forEach(noteRelated);

    const txtRecords = (await dnsPromises.resolveTxt(domain).catch(() => [] as string[][])).map((t) => t.join(''));
    let hasSPF = false;
    txtRecords.forEach((record) => {
        if (!record.toLowerCase().startsWith('v=spf1')) return;
        hasSPF = true;
        details.push(`SPF Record: ${clean(record, 100)}${record.length > 100 ? '...' : ''}`);
        const spf = parseSpf(record);
        spf.includes.slice(0, 20).forEach((inc) => details.push(`Third-party sender: ${clean(inc, 100)}${providerFor(inc) ? ` [${providerFor(inc)}]` : ''}`));
        spf.ranges.slice(0, 20).forEach((range) => details.push(`Declared mail range: ${clean(range, 60)}`));
    });
    servicesFromTxt(txtRecords).forEach((service) => details.push(`SaaS in use: ${service} (domain verification record)`));

    const dmarcRecords = await dnsPromises.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]);
    let hasDMARC = false;
    dmarcRecords.forEach((txt) => {
        const record = txt.join('');
        if (record.toLowerCase().startsWith('v=dmarc1')) {
            hasDMARC = true;
            details.push(`DMARC Record: ${clean(record, 100)}${record.length > 100 ? '...' : ''}`);
        }
    });

    if (mxRecords.length > 0) {
        const selectors = await dkimSelectors(domain);
        if (selectors.length > 0) details.push(`DKIM selectors found: ${selectors.join(', ')}`);
        if (!hasSPF) details.push('⚠️ Email Security: Missing SPF record');
        if (!hasDMARC) details.push('⚠️ Email Security: Missing DMARC record');
    }

    // Wildcard DNS makes every guessed name resolve. Detect it so guessed names
    // are not reported as real hosts.
    const wildcardIps = new Set(await resolve4(`${randomBytes(8).toString('hex')}.${domain}`));
    if (wildcardIps.size > 0) details.push(`Wildcard DNS detected: *.${domain} -> ${Array.from(wildcardIps).join(', ')}`);

    /**
     * Resolves one candidate and records it if it is real. `proven` sources
     * (certificates, DNS records) are trusted even when they resolve to the
     * wildcard address. Guesses are not.
     */
    const tryHost = async (host: string, source: string, proven: boolean): Promise<boolean> => {
        if (tried.has(host) || !inScope(host)) return false;
        tried.add(host);
        const ips = await resolve4(host);
        if (ips.length === 0) return false;
        if (!proven && ips.every((ip) => wildcardIps.has(ip))) return false;
        subdomains.add(host);
        details.push(`Subdomain [${source}]: ${host} -> ${ips.join(', ')}`);
        ips.forEach((ip) => link(ip, host));
        return true;
    };

    // Infrastructure names under the domain are part of the surface.
    await pool(infraHosts.filter(inScope), 20, async (host) => { await tryHost(host, 'dns record', true); });

    // Round 1: the common name list and the certificate logs, side by side.
    const staleNames: string[] = [];
    const [, ct] = await Promise.all([
        pool(COMMON_SUBDOMAINS.map((label) => `${label}.${domain}`), 40, async (host) => { await tryHost(host, 'common name', false); }),
        certificateLogNames(domain),
    ]);
    if (ct.source) {
        details.push(`Certificate logs (${ct.source}): ${ct.names.length} names on record for ${domain}`);
        await pool(ct.names, 40, async (host) => {
            if (tried.has(host)) return;
            if (!(await tryHost(host, 'certificate log', true))) staleNames.push(host);
        });
    } else {
        details.push('Certificate logs: no log source could be reached, so this step was skipped');
    }

    // Round 2: read the certificate each host presents. The names on it reveal
    // sibling services and other domains run by the same organisation. The model
    // is asked for likely names at the same time, if a key is configured.
    const harvestCertificates = async (hosts: string[]) => {
        const fresh: string[] = [];
        await pool(hosts.slice(0, 60), 20, async (host) => {
            const ip = Object.keys(hostMap).find((addr) => hostMap[addr].includes(host));
            if (!ip || !isScannableIp(ip)) return;
            const info = await extractSSLInfo(ip, 443, host);
            if (host === domain) {
                if (info.issuer) {
                    details.push(`SSL Certificate Issuer: ${info.issuer}`);
                    details.push(`SSL Certificate Expires: ${info.validTo}`);
                }
                info.issues.forEach((issue) => details.push(`⚠️ SSL: ${issue.text}`));
            }
            for (const san of info.sans) {
                if (!inScope(san)) noteRelated(san);
                else if (!tried.has(san)) fresh.push(san);
            }
        });
        const unique = Array.from(new Set(fresh)).slice(0, 100);
        await pool(unique, 40, async (host) => {
            if (!(await tryHost(host, 'host certificate', true)) && !staleNames.includes(host)) staleNames.push(host);
        });
    };

    const firstRound = [domain, ...subdomains];
    const [, aiNames] = await Promise.all([
        harvestCertificates(firstRound),
        aiCandidates(domain, Array.from(subdomains)),
    ]);

    // Round 3: names guessed from the naming pattern of what was found.
    const beforeGuessing = new Set(subdomains);
    await pool(patternCandidates(domain, Array.from(subdomains)), 40, async (host) => { await tryHost(host, 'naming pattern', false); });
    if (aiNames.length > 0) {
        let hits = 0;
        await pool(aiNames, 40, async (host) => { if (await tryHost(host, 'AI suggestion', false)) hits++; });
        details.push(`AI name suggestions: ${aiNames.length} tried, ${hits} resolved`);
    }
    const lateFinds = Array.from(subdomains).filter((h) => !beforeGuessing.has(h));
    if (lateFinds.length > 0) await harvestCertificates(lateFinds);

    if (staleNames.length > 0) {
        details.push(`Stale names: ${staleNames.length} names from certificates no longer resolve. Check each for a leftover record that points at a retired service.`);
        staleNames.slice(0, 40).forEach((host) => details.push(`Stale name: ${host}`));
    }

    // Alias chains show which cloud or SaaS platform sits behind each name.
    await pool([domain, ...subdomains, ...staleNames].slice(0, 200), 30, async (host) => {
        const chain = await cnameChain(host);
        if (chain.length === 0) return;
        const provider = chain.map(providerFor).find(Boolean);
        details.push(`Alias: ${host} -> ${chain.join(' -> ')}${provider ? ` [${provider}]` : ''}`);
        chain.filter((h) => !inScope(h)).forEach(noteRelated);
    });

    // Who each address block belongs to. A block assigned to the organisation
    // itself is worth scanning in full. A shared cloud or CDN block is not.
    const owners = new Map<string, string[]>();
    await pool(Object.keys(hostMap).filter(isScannableIp).slice(0, 15), 5, async (ip) => {
        const owner = await networkOwner(ip);
        if (!owner) return;
        const key = `${owner.name}${owner.range ? `, ${owner.range}` : ''}${owner.country ? `, ${owner.country}` : ''}`;
        owners.set(key, [...(owners.get(key) || []), ip]);
    });
    owners.forEach((ips, owner) => details.push(`Network owner: ${ips.join(', ')} -> ${clean(owner, 160)}`));

    const relatedDomains = Array.from(related).sort().slice(0, 40);
    relatedDomains.forEach((d) => details.push(`Related domain: ${d} (shares a certificate or infrastructure record, not scanned)`));

    return {
        ips: Object.keys(hostMap),
        details,
        hostMap,
        subdomains: Array.from(subdomains).sort(),
        subdomainCount: subdomains.size,
        staleNames,
        relatedDomains,
    };
}

export async function reverseDns(ip: string): Promise<string[]> {
    try {
        return await dnsPromises.reverse(ip);
    } catch {
        return [];
    }
}

export interface TargetResolution {
    /** Normalised target string. */
    target: string;
    kind: 'ip' | 'cidr' | 'domain';
    ips: string[];
    mappings: Record<string, string[]>;
    discoveryDetails: string[];
    subdomainCount: number;
}

/** Validates the target and expands it into the list of IPs to scan. Throws TargetError on bad input. */
export async function getTargetIps(rawTarget: string): Promise<TargetResolution> {
    const parsed = parseTarget(rawTarget);
    let ips: string[] = [];
    let mappings: Record<string, string[]> = {};
    let discoveryDetails: string[] = [];
    let subdomainCount = 0;

    if (parsed.kind === 'cidr') {
        ips = parsed.ips;
    } else if (parsed.kind === 'ip') {
        ips = [parsed.value];
    } else {
        const resolved = await resolveDomain(parsed.value);
        discoveryDetails = resolved.details;
        subdomainCount = resolved.subdomainCount;
        mappings = resolved.hostMap;

        // A public name can point at loopback or link-local space. Never follow it there.
        const skipped = resolved.ips.filter((ip) => !isScannableIp(ip));
        skipped.forEach((ip) => delete mappings[ip]);
        if (skipped.length > 0) {
            discoveryDetails.push(`Skipped non-routable addresses: ${skipped.join(', ')}`);
        }
        ips = resolved.ips.filter(isScannableIp);
    }

    ips = ips.slice(0, MAX_IPS_PER_SCAN);

    await Promise.all(ips.slice(0, 50).map(async (ip) => {
        const ptrs = await reverseDns(ip);
        if (ptrs.length === 0) return;
        if (!mappings[ip]) mappings[ip] = [];
        ptrs.forEach((p) => {
            const name = p.toLowerCase();
            if (!mappings[ip].includes(name)) mappings[ip].push(name);
        });
        discoveryDetails.push(`Reverse DNS: ${ip} -> ${ptrs.join(', ')}`);
    }));

    return { target: parsed.value, kind: parsed.kind, ips, mappings, discoveryDetails, subdomainCount };
}

async function probePort(ip: string, port: number, hostname: string | undefined, ptrRecords: string[]): Promise<ScanResult | null> {
    if (!(await checkPort(ip, port))) return null;

    const meta = COMMON_PORTS[port];
    const rawBanner = await grabBanner(ip, port);
    const banner = rawBanner ? clean(rawBanner, MAX_BANNER_BYTES) : null;

    const isWeb = WEB_PORTS.has(port);
    const web = isWeb ? await fetchWebDetails(ip, port, hostname) : null;

    // Fingerprint on the raw banner plus the Server header, so HTTPS services are covered too.
    const fingerprint = [banner, web?.server].filter(Boolean).join(' ');
    const version = extractVersion(fingerprint || null);
    const { issues, forensics, upstreamVersion } = assessService(meta.service, port, fingerprint, version);

    if (banner) {
        const oneLine = banner.replace(/\s+/g, ' ');
        forensics.push(`Banner captured: "${oneLine.slice(0, 60)}${oneLine.length > 60 ? '...' : ''}"`);
    }
    if (ptrRecords.length > 0) forensics.push(`Reverse DNS: ${ptrRecords.join(', ')}`);

    let extraInfo = '';
    if (web?.reached) {
        if (web.title) extraInfo += ` [Title: ${web.title}]`;
        if (web.server) extraInfo += ` [Server: ${web.server}]`;
        issues.push(...web.issues);
        forensics.push(`Web probe: title "${web.title || 'none'}", server "${web.server || 'not disclosed'}"`);
        if (web.tech.length > 0) forensics.push(`Tech stack identified: ${web.tech.join(', ')}`);
    }

    if (TLS_PORTS.has(port)) {
        const sslInfo = await extractSSLInfo(ip, port, hostname);
        if (sslInfo.issuer) forensics.push(`TLS certificate: issued by ${sslInfo.issuer}, expires ${sslInfo.validTo}`);
        issues.push(...sslInfo.issues);
        if (sslInfo.sans.length > 0) {
            forensics.push(`TLS SANs: ${sslInfo.sans.slice(0, 10).join(', ')}${sslInfo.sans.length > 10 ? '...' : ''}`);
        }
    }

    const fixes = Array.from(new Set(issues.map((i) => i.fix).filter(Boolean)));
    const defaultFix = 'Restrict access to this port with a firewall and keep the software on a supported release.';

    return {
        ip,
        port,
        service: meta.service,
        version,
        banner: banner || undefined,
        severity: maxSeverity(meta.severity, ...issues.map((i) => i.severity)),
        description: `${meta.description}. System: ${guessSystem(port, fingerprint)}.${extraInfo}`,
        vulnerability: issues.map((i) => i.text).join('; ') || undefined,
        remediation: issues.length > 0 ? fixes.join(' ') || defaultFix : undefined,
        forensics: forensics.join('\n'),
        upstreamVersion,
        techStack: web?.tech.join(', ') || undefined,
    };
}

/** Probes the common port list on one host. Hosts with no open ports return an empty list. */
export async function scanIp(ip: string, hostname?: string): Promise<ScanResult[]> {
    if (!isScannableIp(ip)) return [];
    const ptrRecords = await reverseDns(ip);
    const ports = Object.keys(COMMON_PORTS).map(Number);
    const results = await Promise.all(ports.map((port) => probePort(ip, port, hostname, ptrRecords).catch(() => null)));
    return results.filter((r): r is ScanResult => r !== null);
}
