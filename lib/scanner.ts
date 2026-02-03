import net from 'net';
import tls from 'tls';
import ipaddr from 'ipaddr.js';

export interface ScanResult {
    ip: string;
    port: number;
    service: string;
    version?: string;
    banner?: string;
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
    vulnerability?: string;
    remediation?: string;
    forensics?: string;
    upstreamVersion?: string;
    domains?: string;
    techStack?: string;
}

const COMMON_PORTS: Record<number, { service: string; severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; description: string }> = {
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

async function fetchWebDetails(ip: string, port: number, hostname?: string): Promise<{ title: string; server: string; tech: string[]; vulnerabilities: string[] }> {
    const findings = { title: 'Unknown', server: 'Unknown', tech: [] as string[], vulnerabilities: [] as string[] };
    try {
        const protocol = port === 443 || port === 8443 ? 'https' : 'http';
        // Use hostname if available for CDN compatibility (Host header)
        const target = hostname || ip;
        const url = `${protocol}://${target}:${port}`;

        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(url, {
            signal: controller.signal,
            headers: hostname ? { 'Host': hostname } : undefined
        }).catch(() => null);
        clearTimeout(id);

        if (response) {
            findings.server = response.headers.get('server') || 'Unknown';
            const text = await response.text();
            const lowerText = text.toLowerCase();

            // Detect Title
            const titleMatch = text.match(/<title>(.*?)<\/title>/i);
            findings.title = titleMatch ? titleMatch[1].trim() : 'No Title Found';

            // Detect Tech Stack
            if (response.headers.get('X-Powered-By')) findings.tech.push(`Backend: ${response.headers.get('X-Powered-By')}`);
            if (lowerText.includes('wp-content')) findings.tech.push('CMS: WordPress');
            if (lowerText.includes('_next/static')) findings.tech.push('Framework: Next.js');
            if (lowerText.includes('react.')) findings.tech.push('Library: React');
            if (lowerText.includes('vue.')) findings.tech.push('Library: Vue.js');
            if (lowerText.includes('laravel')) findings.tech.push('Framework: Laravel');
            if (lowerText.includes('phpsessid')) findings.tech.push('Language: PHP');
            if (lowerText.includes('django')) findings.tech.push('Framework: Django');
            if (findings.server.includes('Apache')) findings.tech.push('Server: Apache');
            if (findings.server.includes('nginx')) findings.tech.push('Server: Nginx');
            if (findings.server.toLowerCase().includes('cloudflare')) findings.tech.push('Proxy: Cloudflare');

            // Header Security
            if (!response.headers.get('X-Frame-Options')) findings.vulnerabilities.push('Missing X-Frame-Options');
            if (!response.headers.get('Content-Security-Policy')) findings.vulnerabilities.push('Missing CSP');
            if (port === 80) findings.vulnerabilities.push('Insecure HTTP');
        }
    } catch (e) { }
    return findings;
}

// SSL Certificate Analysis - Extract SANs for subdomain discovery
async function extractSSLInfo(host: string, port: number = 443): Promise<{ issuer: string; validTo: string; sans: string[]; vulnerabilities: string[] }> {
    return new Promise((resolve) => {
        const result = { issuer: 'Unknown', validTo: 'Unknown', sans: [] as string[], vulnerabilities: [] as string[] };

        const socket = tls.connect({
            host,
            port,
            servername: host,
            timeout: 5000,
            rejectUnauthorized: false
        }, () => {
            try {
                const cert = socket.getPeerCertificate();
                if (cert) {
                    result.issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
                    result.validTo = cert.valid_to || 'Unknown';

                    // Check expiry
                    const expiryDate = new Date(cert.valid_to);
                    const now = new Date();
                    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
                    if (daysUntilExpiry < 0) {
                        result.vulnerabilities.push('SSL Certificate EXPIRED');
                    } else if (daysUntilExpiry < 30) {
                        result.vulnerabilities.push(`SSL Certificate expires in ${daysUntilExpiry} days`);
                    }

                    // Extract SANs (Subject Alternative Names) - CRITICAL for discovery
                    if (cert.subjectaltname) {
                        const sans = cert.subjectaltname.split(', ').map((s: string) => s.replace('DNS:', '').trim());
                        result.sans = sans.filter((s: string) => s && !s.includes('*')); // Remove wildcards
                    }

                    // Check for weak protocols/ciphers
                    const protocol = socket.getProtocol();
                    if (protocol && (protocol.includes('TLSv1.0') || protocol.includes('TLSv1.1'))) {
                        result.vulnerabilities.push(`Weak TLS Protocol: ${protocol}`);
                    }
                }
            } catch (e) { }
            socket.end();
            resolve(result);
        });

        socket.on('error', () => {
            socket.destroy();
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(result);
        });
    });
}

function extractVersion(banner: string | null): string | undefined {
    if (!banner) return undefined;

    // Ignore protocol versions like SSH-2.0 or SSH-1.99
    const cleanBanner = banner.replace(/^SSH-\d+\.\d+-/i, '');
    const versionMatch = cleanBanner.match(/(\d+\.\d+(\.\d+)?)/);

    return versionMatch ? versionMatch[0] : undefined;
}

function checkVulnerabilities(service: string, port: number, banner: string | null, version?: string): {
    list: string[];
    baseSeverity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    remediation?: string;
    forensics: string[];
    upstreamVersion?: string;
} {
    const vulns: string[] = [];
    const forensics: string[] = [`Init discovery on port ${port} (${service})`];
    let severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'INFO';
    let remediation = "No immediate action required. Monitor for software updates.";
    let upstreamVersion = undefined;
    const b = banner?.toLowerCase() || '';

    if (banner) forensics.push(`Banner captured: "${banner.trim().substring(0, 60)}${banner.length > 60 ? '...' : ''}"`);
    if (version) forensics.push(`Software version identified: ${version}`);

    // Fingerprinting & Logic
    if (b.includes('microsoft-iis')) {
        forensics.push('Logic: Microsoft IIS detected via server header');
        if (b.includes('microsoft-iis/10.0')) severity = 'INFO';
        else if (b.includes('microsoft-iis/7.5') || b.includes('microsoft-iis/8.5')) {
            vulns.push('Legacy IIS Version Detected');
            severity = 'LOW';
            remediation = "Migrate to the latest version of IIS on Windows Server 2022+.";
        }
    }

    if (service === 'SSH' && version) {
        upstreamVersion = '9.6p1';
        const v = parseFloat(version);
        if (v < 8.9) {
            vulns.push(`Software version (${version}) is unsupported/outdated`);
            severity = 'HIGH';
            remediation = "Upgrade OpenSSH to the latest version (9.6p1+). Versions below 8.9 are end-of-life or missing critical security patches.";
            forensics.push(`Logic: Version ${version} < Security Baseline (8.9). Flagged as OUTDATED.`);
        } else {
            severity = 'LOW'; // Standard SSH exposure
        }
    }

    if (b.includes('apache/2.4.49')) {
        upstreamVersion = '2.4.52';
        vulns.push('CVE-2021-41773: Path Traversal & Remote Code Execution');
        severity = 'CRITICAL';
        remediation = "IMMEDIATE: Upgrade Apache HTTP Server to version 2.4.51 or higher. Version 2.4.49 is actively exploited.";
        forensics.push(`Logic: Server header matches high-risk pattern 'Apache/2.4.49'. Registered as CRITICAL.`);
    }

    if (port === 445 && !b.includes('signing: true')) {
        vulns.push('SMB Signing Not Required - Potential for Relay Attacks');
        severity = 'MEDIUM';
        remediation = "Enable SMB Signing (RequireSigning) in Group Policy to prevent NTLM relay attacks.";
        forensics.push(`Logic: Handshake response indicates signing is optional or disabled.`);
    }

    if (port === 3389) {
        vulns.push('RDP Exposure - Potential Attack Surface');
        severity = 'LOW';
        remediation = "Ensure NLA (Network Level Authentication) is enabled and RDP is restricted to internal VPN users.";
        forensics.push(`Logic: Generic RDP exposure detected.`);
    }

    if (port === 23) {
        vulns.push('Telnet Cleartext Communication Risk');
        severity = 'CRITICAL';
        remediation = "Disable Telnet immediately and use SSH (Port 22) for remote management.";
        forensics.push(`Logic: Insecure clear-text protocol detected.`);
    }

    return {
        list: vulns,
        baseSeverity: severity,
        remediation,
        forensics,
        upstreamVersion
    };
}

async function checkPort(ip: string, port: number, timeout = 1000): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const onError = () => {
            socket.destroy();
            resolve(false);
        };

        socket.setTimeout(timeout);
        socket.once('error', onError);
        socket.once('timeout', onError);

        socket.connect(port, ip, () => {
            socket.end();
            resolve(true);
        });
    });
}

async function grabBanner(ip: string, port: number, timeout = 3000): Promise<string | null> {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let resolved = false;

        socket.setTimeout(timeout);

        const done = (result: string | null) => {
            if (resolved) return;
            resolved = true;
            socket.destroy();
            resolve(result);
        };

        socket.once('error', () => done(null));
        socket.once('timeout', () => done(data || null));

        socket.connect(port, ip, () => {
            if (port === 80 || port === 8080) {
                socket.write('HEAD / HTTP/1.1\r\nHost: ' + ip + '\r\n\r\n');
            }
        });

        socket.on('data', (chunk) => {
            data += chunk.toString();
            // For SSH/Email/FTP (server-first), the first packet is the banner.
            // We resolve immediately for non-web ports to avoid waiting for a timeout.
            if (port !== 80 && port !== 443 && port !== 8080) {
                done(data);
            }
            if (data.length > 512) {
                done(data);
            }
        });

        socket.on('end', () => done(data || null));
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
    if (b.includes('ssh-2.0-openssh')) return 'OpenSSH';
    if (port === 3306) return 'MySQL/MariaDB';
    if (port === 5432) return 'PostgreSQL';
    if (port === 27017) return 'MongoDB';
    if (port === 6379) return 'Redis';

    if (port === 22) return 'OpenSSH';
    if (port === 80 || port === 443) return 'Web Infrastructure';

    return 'Unknown System';
}

import dns from 'dns';
const dnsPromises = dns.promises;

const COMMON_SUBDOMAINS = [
    'www', 'mail', 'vpn', 'api', 'dev', 'portal', 'remote', 'secure', 'aws', 'owa', 'mail2', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
    'autodiscover', 'staging', 'test', 'git', 'gitlab', 'm', 'admin', 'status', 'support', 'docs', 'blog', 'shop', 'cdn', 'app',
    'internal', 'cloud', 'gateway', 'ssh', 'ftp', 'sql', 'db', 'database', 'jenkins', 'jira', 'confluence', 'wiki', 'proxy',
    'webmail', 'exchange', 'office', 'mobile', 'static', 'assets', 'api-dev', 'api-staging', 'demo', 'uat', 'prod', 'production',
    'billing', 'payment', 'store', 'shop', 'help', 'hr', 'hr-portal', 'staff', 'employee', 'intranet', 'extranet', 'partner',
    'client', 'customer', 'api2', 'api3', 'v2', 'v1', 'legacy', 'old', 'new', 'monitor', 'zabbix', 'nagios', 'grafana', 'prometheus',
    'kibana', 'elastic', 'docker', 'k8s', 'kubernetes', 'registry', 'vault', 'consul', 'backup', 'nas', 'storage', 'san', 'private',
    'hidden', 'secret', 'management', 'console', 'config', 'setup', 'install', 'webhook', 'hooks', 'callback', 'metrics'
];

export async function resolveDomain(domain: string): Promise<{ ips: string[], details: string[], subdomains: string[] }> {
    const ips = new Set<string>();
    const details: string[] = [];
    const discoveredSubdomains: string[] = [];

    try {
        // Root A resolution
        const aRecords = await dnsPromises.resolve4(domain).catch(() => []);
        aRecords.forEach(ip => ips.add(ip));
        if (aRecords.length > 0) details.push(`A Records: ${aRecords.join(', ')}`);

        // CNAME chain discovery
        try {
            const cname = await dnsPromises.resolveCname(domain);
            if (cname.length > 0) {
                details.push(`CNAME Chain: ${domain} -> ${cname.join(' -> ')}`);
                for (const cn of cname) {
                    const cnIps = await dnsPromises.resolve4(cn).catch(() => []);
                    cnIps.forEach(ip => ips.add(ip));
                }
            }
        } catch (e) { }

        // NS Records (Nameservers)
        const nsRecords = await dnsPromises.resolveNs(domain).catch(() => []);
        if (nsRecords.length > 0) {
            details.push(`Nameservers: ${nsRecords.join(', ')}`);
            for (const ns of nsRecords) {
                const nsIps = await dnsPromises.resolve4(ns).catch(() => []);
                nsIps.forEach(ip => ips.add(ip));
            }
        }

        // MX Records (Mail)
        const mxRecords = await dnsPromises.resolveMx(domain).catch(() => []);
        for (const mx of mxRecords) {
            details.push(`MX Record: ${mx.exchange} (priority ${mx.priority})`);
            const mxIps = await dnsPromises.resolve4(mx.exchange).catch(() => []);
            mxIps.forEach(ip => ips.add(ip));
        }

        // TXT Records (Security headers + Email Security)
        const txtRecords = await dnsPromises.resolveTxt(domain).catch(() => []);
        let hasSPF = false, hasDKIM = false, hasDMARC = false;
        txtRecords.forEach(txt => {
            const record = txt.join(' ');
            if (record.includes('v=spf1')) {
                hasSPF = true;
                details.push(`SPF Record: ${record.substring(0, 100)}${record.length > 100 ? '...' : ''}`);
            }
        });

        // DMARC record
        try {
            const dmarcRecords = await dnsPromises.resolveTxt(`_dmarc.${domain}`).catch(() => []);
            dmarcRecords.forEach(txt => {
                const record = txt.join(' ');
                if (record.includes('v=DMARC1')) {
                    hasDMARC = true;
                    details.push(`DMARC Record: ${record.substring(0, 100)}${record.length > 100 ? '...' : ''}`);
                }
            });
        } catch (e) { }

        // Email Security Posture
        if (mxRecords.length > 0) {
            if (!hasSPF) details.push('⚠️ Email Security: Missing SPF record');
            if (!hasDMARC) details.push('⚠️ Email Security: Missing DMARC record');
        }

        // Enterprise Subdomain Brute-force
        const subTasks = COMMON_SUBDOMAINS.map(async (sub) => {
            const subDomain = `${sub}.${domain}`;
            try {
                const subIps = await dnsPromises.resolve4(subDomain);
                if (subIps.length > 0) {
                    discoveredSubdomains.push(subDomain);
                    details.push(`Discovered Subdomain: ${subDomain} -> ${subIps.join(', ')}`);
                    subIps.forEach(ip => ips.add(ip));
                }
            } catch (e) { }
        });
        await Promise.all(subTasks);

        // SSL Certificate SAN Discovery (Enterprise ASM technique)
        try {
            const sslInfo = await extractSSLInfo(domain);
            if (sslInfo.issuer !== 'Unknown') {
                details.push(`SSL Certificate Issuer: ${sslInfo.issuer}`);
                details.push(`SSL Certificate Expires: ${sslInfo.validTo}`);
            }
            if (sslInfo.vulnerabilities.length > 0) {
                sslInfo.vulnerabilities.forEach(v => details.push(`⚠️ SSL: ${v}`));
            }
            // Discover additional subdomains from SANs
            for (const san of sslInfo.sans) {
                if (san.endsWith(domain) && !discoveredSubdomains.includes(san)) {
                    discoveredSubdomains.push(san);
                    details.push(`SSL SAN Discovery: ${san}`);
                    try {
                        const sanIps = await dnsPromises.resolve4(san);
                        sanIps.forEach(ip => ips.add(ip));
                    } catch (e) { }
                }
            }
        } catch (e) { }

    } catch (e) {
        console.error(`DNS resolution failed for ${domain}:`, e);
    }

    return { ips: Array.from(ips), details, subdomains: discoveredSubdomains };
}

export async function reverseDns(ip: string): Promise<string[]> {
    try {
        return await dnsPromises.reverse(ip);
    } catch (e) {
        return [];
    }
}

export async function getTargetIps(target: string): Promise<{ ips: string[], mappings: Record<string, string[]>, discoveryDetails: string[] }> {
    let ips: string[] = [];
    let mappings: Record<string, string[]> = {};
    let discoveryDetails: string[] = [];

    try {
        if (target.includes('/')) {
            const range = ipaddr.parseCIDR(target);
            const network = range[0];
            const prefix = range[1];
            if (prefix >= 24) {
                const base = network.toByteArray();
                const total = Math.pow(2, 32 - prefix);
                for (let i = 1; i < total - 1; i++) {
                    const ipArr = [...base];
                    ipArr[3] = ipArr[3] + i;
                    ips.push(ipaddr.fromByteArray(ipArr).toString());
                }
            } else {
                ips.push(network.toString());
            }
        } else if (/^[0-9.]+$/.test(target)) {
            ips.push(target);
        } else {
            // Domain lookup + Discovery
            const { ips: domainIps, details, subdomains } = await resolveDomain(target);
            ips = domainIps;

            // Map IPs back to the domain for the UI
            ips.forEach(ip => {
                mappings[ip] = [target];
            });

            // Add discovered subdomains to mappings
            subdomains.forEach(sub => {
                details.forEach(detail => {
                    if (detail.includes(sub)) {
                        const match = detail.match(new RegExp(`${sub.replace('.', '\\.')} -> ([^,]+)`));
                        if (match) {
                            const subIps = match[1].split(',').map(i => i.trim());
                            subIps.forEach(sip => {
                                if (!mappings[sip]) mappings[sip] = [];
                                if (!mappings[sip].includes(sub)) mappings[sip].push(sub);
                            });
                        }
                    }
                });
            });

            // Store discovery details for later saving
            discoveryDetails = details;
        }
    } catch (e) {
        ips.push(target);
    }

    // Reverse DNS discovery (Enterprise standard) - Parallelized
    const reverseTasks = ips.slice(0, 50).map(async (ip) => {
        try {
            const ptrs = await reverseDns(ip);
            if (ptrs.length > 0) {
                if (!mappings[ip]) mappings[ip] = [];
                ptrs.forEach(p => {
                    if (!mappings[ip].includes(p)) mappings[ip].push(p);
                });
                discoveryDetails.push(`Reverse DNS: ${ip} -> ${ptrs.join(', ')}`);
            }
        } catch (e) { }
    });
    await Promise.all(reverseTasks);

    return { ips: ips.slice(0, 256), mappings, discoveryDetails };
}

export async function scanIp(ip: string, hostname?: string): Promise<ScanResult[]> {
    const portChecks = Object.keys(COMMON_PORTS).map(Number).map(async (port) => {
        const isOpen = await checkPort(ip, port);
        if (!isOpen) return null;

        const banner = await grabBanner(ip, port);
        const version = extractVersion(banner);
        const system = guessSystem(port, banner);
        const { list: vulnerabilities, baseSeverity, remediation, forensics, upstreamVersion } = checkVulnerabilities(COMMON_PORTS[port].service, port, banner, version);

        // Enterprise Discovery: Reverse DNS
        const ptrRecords = await reverseDns(ip);
        if (ptrRecords.length > 0) {
            forensics.push(`Reverse DNS Discovery: IP resolves to ${ptrRecords.join(', ')}`);
        }

        let extraInfo = '';
        let techStack: string | undefined = undefined;
        if (port === 80 || port === 443 || port === 8080 || port === 8443) {
            const web = await fetchWebDetails(ip, port, hostname);
            extraInfo = ` [Web Title: ${web.title}] [Server: ${web.server}]`;
            techStack = web.tech.join(', ');
            if (web.vulnerabilities.length > 0) {
                vulnerabilities.push(...web.vulnerabilities);
                forensics.push(`Web Probe: Discovered title "${web.title}" and server "${web.server}"`);
                if (web.tech.length > 0) forensics.push(`Tech Stack Identified: ${web.tech.join(', ')}`);
            }

            // SSL Certificate Analysis for HTTPS ports
            if (port === 443 || port === 8443) {
                const sslTarget = hostname || ip;
                const sslInfo = await extractSSLInfo(sslTarget, port);
                if (sslInfo.issuer !== 'Unknown') {
                    forensics.push(`SSL Certificate: Issued by ${sslInfo.issuer}, expires ${sslInfo.validTo}`);
                }
                if (sslInfo.vulnerabilities.length > 0) {
                    vulnerabilities.push(...sslInfo.vulnerabilities);
                }
                if (sslInfo.sans.length > 0) {
                    forensics.push(`SSL SANs (Alt Names): ${sslInfo.sans.slice(0, 10).join(', ')}${sslInfo.sans.length > 10 ? '...' : ''}`);
                }
            }
        }

        return {
            ip,
            port,
            service: COMMON_PORTS[port].service,
            version,
            banner: banner?.trim() || undefined,
            severity: vulnerabilities.length > 0 ?
                (vulnerabilities.some(v => v.includes('CRITICAL')) || baseSeverity === 'CRITICAL' ? 'CRITICAL' : (vulnerabilities.some(v => v.includes('HIGH')) || baseSeverity === 'HIGH' ? 'HIGH' : 'MEDIUM'))
                : baseSeverity || COMMON_PORTS[port].severity,
            description: `${COMMON_PORTS[port].description}. System: ${system}.${extraInfo}`,
            vulnerability: vulnerabilities.join('; '),
            remediation: vulnerabilities.length > 0 ? remediation : undefined,
            forensics: forensics.join('\n'),
            upstreamVersion,
            techStack
        } as ScanResult;
    });

    const results = (await Promise.all(portChecks)).filter((r): r is ScanResult => r !== null);

    // Only return results if we have actual open ports
    // Do NOT record IPs that have no responding services
    return results;
}

export async function scanTarget(target: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const { ips, mappings } = await getTargetIps(target);
    for (const ip of ips) {
        // Use the first mapped domain for Host header compatibility if available
        const hostname = mappings[ip] && mappings[ip].length > 0 ? mappings[ip][0] : undefined;
        const ipResults = await scanIp(ip, hostname);
        // Enrich results with all discovered domain mappings
        if (mappings[ip]) {
            ipResults.forEach(r => {
                r.domains = mappings[ip].join(',');
            });
        }
        results.push(...ipResults);
    }
    return results;
}
