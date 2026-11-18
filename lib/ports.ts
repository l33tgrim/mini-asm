/**
 * Which TCP ports a scan checks. Pure data and parsing, so the scan form can
 * show a live port count and the server can validate the same input.
 */

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface PortMeta {
    service: string;
    severity: Severity;
    description: string;
}

/** The default scan list. Every port here has a known service and risk rating. */
export const COMMON_PORTS: Record<number, PortMeta> = {
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

/** Names for ports the presets add on top of the default list. */
const OTHER_PORTS: Record<number, PortMeta> = {
    81: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port' },
    102: { service: 'S7comm', severity: 'CRITICAL', description: 'Siemens S7 PLC protocol' },
    502: { service: 'Modbus', severity: 'CRITICAL', description: 'Modbus industrial control protocol, no authentication' },
    512: { service: 'rexec', severity: 'CRITICAL', description: 'Remote execution service, clear text' },
    513: { service: 'rlogin', severity: 'CRITICAL', description: 'Remote login service, clear text' },
    514: { service: 'rsh', severity: 'CRITICAL', description: 'Remote shell service, clear text' },
    591: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port' },
    789: { service: 'Red Lion', severity: 'HIGH', description: 'Red Lion Crimson industrial protocol' },
    1434: { service: 'MSSQL-Monitor', severity: 'HIGH', description: 'SQL Server browser service' },
    1701: { service: 'L2TP', severity: 'LOW', description: 'Layer 2 Tunnelling Protocol' },
    1911: { service: 'Niagara Fox', severity: 'HIGH', description: 'Tridium Niagara building automation' },
    1962: { service: 'PCWorx', severity: 'HIGH', description: 'Phoenix Contact PLC protocol' },
    2379: { service: 'etcd', severity: 'CRITICAL', description: 'etcd key store, often holds cluster secrets' },
    2404: { service: 'IEC-104', severity: 'CRITICAL', description: 'IEC 60870-5-104 power grid telecontrol' },
    2525: { service: 'SMTP-Alt', severity: 'MEDIUM', description: 'Alternative mail submission port' },
    3283: { service: 'Apple Remote Desktop', severity: 'HIGH', description: 'Apple Remote Desktop' },
    4243: { service: 'Docker-Alt', severity: 'CRITICAL', description: 'Docker API on an alternative port' },
    4840: { service: 'OPC UA', severity: 'HIGH', description: 'OPC UA industrial data exchange' },
    4899: { service: 'Radmin', severity: 'HIGH', description: 'Radmin remote administration' },
    5000: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port, often a container registry or dev server' },
    5601: { service: 'Kibana', severity: 'HIGH', description: 'Kibana dashboard' },
    5901: { service: 'VNC', severity: 'HIGH', description: 'Virtual Network Computing, display 1' },
    5902: { service: 'VNC', severity: 'HIGH', description: 'Virtual Network Computing, display 2' },
    5903: { service: 'VNC', severity: 'HIGH', description: 'Virtual Network Computing, display 3' },
    5938: { service: 'TeamViewer', severity: 'HIGH', description: 'TeamViewer remote access' },
    5984: { service: 'CouchDB', severity: 'HIGH', description: 'CouchDB database API' },
    7001: { service: 'WebLogic', severity: 'HIGH', description: 'Oracle WebLogic admin and web port' },
    7070: { service: 'AnyDesk', severity: 'HIGH', description: 'AnyDesk remote access' },
    7474: { service: 'Neo4j', severity: 'HIGH', description: 'Neo4j database browser' },
    8001: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port, often a Kubernetes proxy' },
    8008: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port' },
    8081: { service: 'HTTP-Alt', severity: 'INFO', description: 'Alternative web port' },
    8086: { service: 'InfluxDB', severity: 'HIGH', description: 'InfluxDB time series database' },
    8200: { service: 'Vault', severity: 'HIGH', description: 'HashiCorp Vault API' },
    8291: { service: 'Winbox', severity: 'HIGH', description: 'MikroTik Winbox router management' },
    8500: { service: 'Consul', severity: 'HIGH', description: 'HashiCorp Consul API' },
    8529: { service: 'ArangoDB', severity: 'HIGH', description: 'ArangoDB database' },
    9042: { service: 'Cassandra', severity: 'HIGH', description: 'Cassandra database' },
    9090: { service: 'Prometheus', severity: 'MEDIUM', description: 'Prometheus or a management console' },
    9093: { service: 'Alertmanager', severity: 'MEDIUM', description: 'Prometheus Alertmanager' },
    9100: { service: 'Node exporter', severity: 'MEDIUM', description: 'Prometheus node exporter or printer port' },
    9300: { service: 'Elasticsearch', severity: 'HIGH', description: 'Elasticsearch cluster transport' },
    9600: { service: 'Omron FINS', severity: 'HIGH', description: 'Omron PLC protocol' },
    10000: { service: 'Webmin', severity: 'HIGH', description: 'Webmin server administration' },
    10255: { service: 'Kubelet-RO', severity: 'HIGH', description: 'Kubernetes kubelet read-only API' },
    10443: { service: 'SSL VPN', severity: 'MEDIUM', description: 'Common SSL VPN portal port' },
    15672: { service: 'RabbitMQ', severity: 'MEDIUM', description: 'RabbitMQ management console' },
    20000: { service: 'DNP3', severity: 'CRITICAL', description: 'DNP3 utility control protocol' },
    27018: { service: 'MongoDB', severity: 'HIGH', description: 'MongoDB shard server' },
    27019: { service: 'MongoDB', severity: 'HIGH', description: 'MongoDB config server' },
    28017: { service: 'MongoDB-Web', severity: 'HIGH', description: 'Legacy MongoDB web status page' },
    44818: { service: 'EtherNet/IP', severity: 'CRITICAL', description: 'Rockwell EtherNet/IP industrial protocol' },
    50000: { service: 'DB2', severity: 'HIGH', description: 'IBM DB2 or SAP service' },
    50070: { service: 'Hadoop', severity: 'HIGH', description: 'Hadoop NameNode web interface' },
};

const UNKNOWN: PortMeta = { service: 'Unknown', severity: 'LOW', description: 'Open port that is not on the known service list' };

/** Service name and baseline risk for a TCP port, or a generic entry for unlisted ports. */
export function portMeta(port: number): PortMeta {
    return COMMON_PORTS[port] ?? OTHER_PORTS[port] ?? UNKNOWN;
}

export const DEFAULT_TCP_PORTS = Object.keys(COMMON_PORTS).map(Number);

export interface PortPreset {
    id: string;
    label: string;
    spec: string;
}

export const PORT_PRESETS: PortPreset[] = [
    { id: 'default', label: 'Default list', spec: DEFAULT_TCP_PORTS.join(',') },
    { id: 'remote-access', label: 'Remote access', spec: '22,23,512-514,2222,3283,3389,4899,5900-5903,5938,5985,5986,7070,8291,10000' },
    { id: 'databases', label: 'Databases and caches', spec: '1433,1434,1521,2379,3306,5432,5984,6379,7474,8086,8529,9042,9200,9300,11211,27017-27019,28017,50000' },
    { id: 'vpn', label: 'VPN and gateways', spec: '443,500,1194,1701,1723,4443,4500,8443,10443' },
    { id: 'admin', label: 'Admin and DevOps', spec: '2375,2376,2379,3000,4243,5000,5601,6443,8001,8080,8200,8443,8500,9000,9090,9093,9100,10250,10255,15672,50070' },
    { id: 'web', label: 'Web', spec: '80,81,443,591,3000,5000,7001,8000,8001,8008,8080-8090,8443,8888,9000,9443' },
    { id: 'mail', label: 'Mail', spec: '25,110,143,465,587,993,995,2525' },
    { id: 'ics', label: 'Industrial control', spec: '102,502,789,1911,1962,2404,4840,9600,20000,44818' },
    { id: 'well-known', label: 'All of 1 to 1024', spec: '1-1024' },
];

/** Upper limit on TCP ports per host, so one scan cannot run for hours. */
export const MAX_PORTS_PER_HOST = 5000;
/** Upper limit on host and port pairs per scan: about 17 minutes if every port is filtered. */
export const MAX_PROBES_PER_SCAN = 100_000;

export class PortSpecError extends Error { }

/**
 * Parses input like "default, 8000-8100, 10443" or "remote-access,databases".
 * Accepts preset ids, single ports and ranges, separated by commas or spaces.
 * Empty input means the default list.
 */
export function parsePortSpec(input: string | null | undefined): number[] {
    const text = (input ?? '').trim().toLowerCase();
    if (!text) return [...DEFAULT_TCP_PORTS];

    const ports = new Set<number>();
    const add = (n: number) => {
        if (ports.size >= MAX_PORTS_PER_HOST && !ports.has(n)) {
            throw new PortSpecError(`That is more than ${MAX_PORTS_PER_HOST.toLocaleString('en')} ports. Narrow the range.`);
        }
        ports.add(n);
    };
    const check = (n: number, token: string) => {
        if (!Number.isInteger(n) || n < 1 || n > 65535) throw new PortSpecError(`"${token}" is not a port between 1 and 65535.`);
        return n;
    };

    for (const token of text.split(/[\s,;]+/).filter(Boolean)) {
        const preset = PORT_PRESETS.find((p) => p.id === token);
        if (preset) {
            parsePortSpec(preset.spec).forEach(add);
            continue;
        }
        const range = token.match(/^(\d+)-(\d+)$/);
        if (range) {
            const from = check(Number(range[1]), token);
            const to = check(Number(range[2]), token);
            if (from > to) throw new PortSpecError(`"${token}" runs backwards. Put the lower port first.`);
            if (to - from + 1 > MAX_PORTS_PER_HOST) {
                throw new PortSpecError(`That is more than ${MAX_PORTS_PER_HOST.toLocaleString('en')} ports. Narrow the range.`);
            }
            for (let n = from; n <= to; n++) add(n);
            continue;
        }
        if (/^\d+$/.test(token)) {
            add(check(Number(token), token));
            continue;
        }
        throw new PortSpecError(`"${token}" is not a port, a range like 8000-8100, or a preset name.`);
    }
    return [...ports].sort((a, b) => a - b);
}
