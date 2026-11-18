/**
 * UDP service probes. UDP has no handshake, so a port only counts as open when
 * the service sends back a valid reply to a real protocol request. Silence is
 * not proof of anything: the port may be closed, filtered, or the service may
 * ignore requests it does not like. Every probe here is a read-only request
 * that a normal client would send.
 */
import dgram from 'dgram';
import net from 'net';
import { randomBytes } from 'crypto';
import type { Severity } from './ports';

export interface UdpFinding {
    ip: string;
    port: number;
    protocol: 'udp';
    service: string;
    version?: string;
    banner?: string;
    severity: Severity;
    description: string;
    vulnerability?: string;
    remediation?: string;
    forensics?: string;
}

export interface UdpExchange {
    replies: Buffer[];
    /** The host sent ICMP port unreachable, so nothing listens there. */
    refused: boolean;
    bytes: number;
}

const RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const worst = (...s: Severity[]) => s.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'INFO' as Severity);

/** Printable text only, so remote data is safe to store and render. */
function text(buf: Buffer | string, max = 300): string {
    const s = typeof buf === 'string' ? buf : buf.toString('latin1');
    return s.replace(/[^\x20-\x7e\n\t]/g, '').trim().slice(0, max);
}

/**
 * Sends one datagram and collects replies. A connected socket lets the OS hand
 * back ICMP port unreachable as ECONNREFUSED. Resolves after `timeout`, or
 * `settle` ms after the first reply when more fragments may follow.
 */
export function exchange(ip: string, port: number, payload: Buffer, timeout = 2000, settle = 400): Promise<UdpExchange> {
    return new Promise((resolve) => {
        const socket = dgram.createSocket(net.isIPv6(ip) ? 'udp6' : 'udp4');
        const result: UdpExchange = { replies: [], refused: false, bytes: 0 };
        let finished = false;
        let timer: NodeJS.Timeout;
        const finish = () => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            try { socket.close(); } catch { /* already closed */ }
            resolve(result);
        };
        timer = setTimeout(finish, timeout);
        socket.on('error', (err: NodeJS.ErrnoException) => {
            if (err.code === 'ECONNREFUSED') result.refused = true;
            finish();
        });
        socket.on('message', (msg) => {
            result.bytes += msg.length;
            if (result.replies.length < 50) result.replies.push(msg);
            if (result.replies.length === 1) {
                clearTimeout(timer);
                timer = setTimeout(finish, settle);
            }
        });
        socket.connect(port, ip, () => {
            socket.send(payload, (err) => { if (err) finish(); });
        });
    });
}

function evidence(name: string, sent: number, x: UdpExchange): string {
    const factor = sent > 0 ? (x.bytes / sent).toFixed(1) : '0';
    return `Sent ${name} (${sent} bytes), got ${x.replies.length} ${x.replies.length === 1 ? 'reply' : 'replies'} totalling ${x.bytes} bytes (${factor}x)`;
}

/* ------------------------------------------------------------------ NTP */

export const NTP_CLIENT = (() => { const b = Buffer.alloc(48); b[0] = 0x23; return b; })(); // v4, mode 3
export const NTP_READVAR = (() => { const b = Buffer.alloc(12); b[0] = 0x16; b[1] = 0x02; b.writeUInt16BE(1, 2); return b; })(); // v2, mode 6, op 2
export const NTP_MONLIST = (() => { const b = Buffer.alloc(48); b[0] = 0x17; b[1] = 0x00; b[2] = 0x03; b[3] = 0x2a; return b; })(); // v2, mode 7, MON_GETLIST_1

export interface NtpTime { version: number; stratum: number; refid: string; serverTime?: string }

export function parseNtpTime(buf: Buffer): NtpTime | null {
    if (buf.length < 48 || (buf[0] & 0x07) !== 4) return null;
    const stratum = buf[1];
    const ref = buf.subarray(12, 16);
    const refid = stratum <= 1 ? text(ref, 4) : Array.from(ref).join('.');
    const seconds = buf.readUInt32BE(40);
    const serverTime = seconds > 2208988800 ? new Date((seconds - 2208988800) * 1000).toISOString() : undefined;
    return { version: (buf[0] >> 3) & 0x07, stratum, refid, serverTime };
}

/** Joins mode 6 response fragments and splits the key=value list. */
export function parseNtpVariables(replies: Buffer[]): Record<string, string> | null {
    const parts = replies
        .filter((b) => b.length >= 12 && (b[0] & 0x07) === 6 && (b[1] & 0x80) && !(b[1] & 0x40))
        .map((b) => ({ offset: b.readUInt16BE(8), data: b.subarray(12, 12 + b.readUInt16BE(10)) }))
        .sort((a, b) => a.offset - b.offset);
    if (parts.length === 0) return null;
    const body = text(Buffer.concat(parts.map((p) => p.data)), 2000);
    const vars: Record<string, string> = {};
    for (const m of body.matchAll(/([\w.]+)=("([^"]*)"|[^,]*)/g)) vars[m[1]] = (m[3] ?? m[2]).trim();
    return vars;
}

export function parseMonlist(replies: Buffer[]): { ok: boolean; items: number } {
    const valid = replies.filter((b) => b.length >= 8 && (b[0] & 0x80) && (b[0] & 0x07) === 7 && b[3] === 0x2a);
    const ok = valid.some((b) => b[4] >> 4 === 0);
    return { ok, items: valid.reduce((n, b) => n + (b.readUInt16BE(4) & 0x0fff), 0) };
}

export async function probeNtp(ip: string, port = 123, timeout = 2000): Promise<UdpFinding | null> {
    const [time, vars, mon] = await Promise.all([
        exchange(ip, port, NTP_CLIENT, timeout),
        exchange(ip, port, NTP_READVAR, timeout),
        exchange(ip, port, NTP_MONLIST, timeout, 800),
    ]);
    const t = time.replies.map(parseNtpTime).find(Boolean) ?? null;
    const v = parseNtpVariables(vars.replies);
    const m = parseMonlist(mon.replies);
    if (!t && !v && !m.ok) return null;

    const forensics = [`UDP ${port} answered NTP requests`];
    const issues: { text: string; severity: Severity; fix: string }[] = [];
    let version: string | undefined;
    let banner = '';

    if (t) {
        forensics.push(evidence('NTP mode 3 client request', NTP_CLIENT.length, time));
        forensics.push(`NTPv${t.version}, stratum ${t.stratum}, reference ${t.refid || 'none'}${t.serverTime ? `, server clock ${t.serverTime}` : ''}`);
        banner = `NTPv${t.version} stratum ${t.stratum} refid ${t.refid}`;
    }
    if (v) {
        forensics.push(evidence('NTP mode 6 READVAR', NTP_READVAR.length, vars));
        const shown = ['version', 'system', 'processor', 'stratum', 'refid'].filter((k) => v[k]).map((k) => `${k}=${v[k]}`);
        if (shown.length) forensics.push(`Server variables: ${shown.join(', ')}`);
        banner = text(v.version || banner, 200);
        version = v.version?.match(/ntpd\s+([\d.]+(?:p\d+)?)/i)?.[1];
        if (v.system) forensics.push(`Operating system reported by ntpd: ${v.system}`);
        issues.push({
            text: 'NTP control queries (mode 6) answered: the server discloses its software version and OS',
            severity: 'MEDIUM',
            fix: 'Add "restrict default kod nomodify notrap nopeer noquery" to ntp.conf, or move to chrony which refuses these queries by default.',
        });
        const [maj, min, patch] = (version ?? '').split(/[.p]/).map(Number);
        if (version && (maj < 4 || (maj === 4 && min < 2) || (maj === 4 && min === 2 && patch < 8))) {
            issues.push({
                text: `ntpd ${version} is older than 4.2.8, which fixed CVE-2014-9295 and other remotely exploitable bugs`,
                severity: 'HIGH',
                fix: 'Upgrade ntpd to the current 4.2.8 release or replace it with chrony.',
            });
        }
    }
    if (m.ok) {
        forensics.push(evidence('NTP mode 7 MON_GETLIST (monlist)', NTP_MONLIST.length, mon));
        forensics.push(`monlist returned ${m.items} recent client entries`);
        issues.push({
            text: 'CVE-2013-5211: monlist is enabled, so the server can be used for DDoS amplification and leaks recent client addresses',
            severity: 'HIGH',
            fix: 'Upgrade ntpd to 4.2.7p26 or later, or add "disable monitor" to ntp.conf. Block UDP 123 from the internet unless this is a public time server.',
        });
    }

    const exposed = issues.length === 0;
    return {
        ip, port, protocol: 'udp',
        service: 'NTP',
        version,
        banner: banner || undefined,
        severity: worst('LOW', ...issues.map((i) => i.severity)),
        description: exposed
            ? 'Network Time Protocol answers time requests. Normal for a time server, otherwise limit it to internal clients'
            : 'Network Time Protocol answers more than time requests',
        vulnerability: issues.map((i) => i.text).join('; ') || undefined,
        remediation: issues.map((i) => i.fix).join(' ') || 'If this host is not meant to serve time to the internet, block UDP 123 inbound at the edge.',
        forensics: forensics.join('\n'),
    };
}

/* ------------------------------------------------------------------ BER / SNMP */

function berLen(n: number): Buffer {
    if (n < 0x80) return Buffer.from([n]);
    if (n < 0x100) return Buffer.from([0x81, n]);
    return Buffer.from([0x82, n >> 8, n & 0xff]);
}
function tlv(tag: number, ...parts: Buffer[]): Buffer {
    const body = Buffer.concat(parts);
    return Buffer.concat([Buffer.from([tag]), berLen(body.length), body]);
}
function berInt(n: number): Buffer {
    const bytes: number[] = [];
    do { bytes.unshift(n & 0xff); n = Math.floor(n / 256); } while (n > 0);
    if (bytes[0] & 0x80) bytes.unshift(0);
    return tlv(0x02, Buffer.from(bytes));
}
const berStr = (s: string | Buffer) => tlv(0x04, Buffer.isBuffer(s) ? s : Buffer.from(s, 'latin1'));
function berOid(oid: string): Buffer {
    const p = oid.split('.').map(Number);
    const out = [40 * p[0] + p[1]];
    for (const n of p.slice(2)) {
        const b = [n & 0x7f];
        for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) b.unshift((v & 0x7f) | 0x80);
        out.push(...b);
    }
    return tlv(0x06, Buffer.from(out));
}

export interface Ber { tag: number; value: Buffer; children?: Ber[] }

export function berDecode(buf: Buffer, start = 0, end = buf.length, depth = 0): Ber[] {
    if (depth > 10) throw new Error('BER nested too deep');
    const out: Ber[] = [];
    let i = start;
    while (i < end) {
        const tag = buf[i++];
        let len = buf[i++];
        if (len === undefined) throw new Error('BER truncated');
        if (len & 0x80) {
            const n = len & 0x7f;
            if (n < 1 || n > 3) throw new Error('BER length not supported');
            len = 0;
            for (let k = 0; k < n; k++) len = len * 256 + buf[i++];
        }
        if (i + len > end) throw new Error('BER truncated');
        const node: Ber = { tag, value: buf.subarray(i, i + len) };
        if (tag & 0x20) node.children = berDecode(buf, i, i + len, depth + 1);
        out.push(node);
        i += len;
    }
    return out;
}
const berToInt = (b: Buffer) => b.reduce((n, x) => n * 256 + x, 0);

const SYS_DESCR = '1.3.6.1.2.1.1.1.0';
const SYS_NAME = '1.3.6.1.2.1.1.5.0';

/** SNMP v1 (version 0) or v2c (version 1) GetRequest for sysDescr.0 and sysName.0. */
export function snmpGetRequest(version: 0 | 1, community: string, requestId: number): Buffer {
    const varbinds = tlv(0x30, ...[SYS_DESCR, SYS_NAME].map((oid) => tlv(0x30, berOid(oid), Buffer.from([0x05, 0x00]))));
    const pdu = tlv(0xa0, berInt(requestId), berInt(0), berInt(0), varbinds);
    return tlv(0x30, berInt(version), berStr(community), pdu);
}

/** Returns the string values of a GetResponse, keyed by OID position, or null if it is not one. */
export function parseSnmpResponse(buf: Buffer): { descr?: string; name?: string } | null {
    try {
        const msg = berDecode(buf)[0];
        const pdu = msg?.children?.[2];
        if (msg?.tag !== 0x30 || pdu?.tag !== 0xa2) return null;
        const binds = pdu.children?.[3]?.children ?? [];
        const values = binds.map((b) => b.children?.[1]).map((v) => (v?.tag === 0x04 ? text(v.value, 400) : undefined));
        return { descr: values[0], name: values[1] };
    } catch {
        return null;
    }
}

/** SNMPv3 discovery: an unauthenticated GetRequest the agent answers with its engine ID. */
export function snmpV3Discovery(msgId: number): Buffer {
    const header = tlv(0x30, berInt(msgId), berInt(65507), berStr(Buffer.from([0x04])), berInt(3));
    const usm = tlv(0x30, berStr(''), berInt(0), berInt(0), berStr(''), berStr(''), berStr(''));
    const scoped = tlv(0x30, berStr(''), berStr(''), tlv(0xa0, berInt(msgId), berInt(0), berInt(0), tlv(0x30)));
    return tlv(0x30, berInt(3), header, berStr(usm), scoped);
}

const ENTERPRISES: Record<number, string> = {
    9: 'Cisco', 11: 'HP', 311: 'Microsoft', 674: 'Dell', 2011: 'Huawei', 2636: 'Juniper', 4526: 'Netgear',
    6876: 'VMware', 8072: 'net-snmp', 12356: 'Fortinet', 14988: 'MikroTik', 25461: 'Palo Alto Networks', 3375: 'F5', 1991: 'Brocade',
    6486: 'Alcatel-Lucent', 2620: 'Check Point', 25506: 'H3C', 41112: 'Ubiquiti', 30065: 'Arista', 21067: 'Sophos',
};

export interface SnmpEngine { engineId: string; vendor?: string; boots: number; time: number; mac?: string; address?: string }

export function parseSnmpV3Report(buf: Buffer): SnmpEngine | null {
    try {
        const msg = berDecode(buf)[0];
        if (msg?.tag !== 0x30 || berToInt(msg.children?.[0]?.value ?? Buffer.alloc(0)) !== 3) return null;
        const usm = berDecode(msg.children![2].value)[0]?.children;
        const id = usm?.[0]?.value;
        if (!id || id.length === 0) return null;
        const engine: SnmpEngine = { engineId: id.toString('hex'), boots: berToInt(usm![1].value), time: berToInt(usm![2].value) };
        if (id.length >= 5 && id[0] & 0x80) {
            const ent = id.readUInt32BE(0) & 0x7fffffff;
            engine.vendor = ENTERPRISES[ent] ?? `enterprise ${ent}`;
            const data = id.subarray(5);
            if (id[4] === 1 && data.length === 4) engine.address = Array.from(data).join('.');
            if (id[4] === 3 && data.length === 6) engine.mac = Array.from(data).map((b) => b.toString(16).padStart(2, '0')).join(':');
        } else if (id.length >= 4) {
            engine.vendor = ENTERPRISES[id.readUInt32BE(0) & 0x7fffffff];
        }
        return engine;
    } catch {
        return null;
    }
}

function uptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((seconds % 3600) / 60)}m`;
}

/** Default community strings tested. Both are factory defaults on many devices. */
export const SNMP_COMMUNITIES = ['public', 'private'];

export async function probeSnmp(ip: string, port = 161, timeout = 2000): Promise<UdpFinding | null> {
    const id = randomBytes(2).readUInt16BE(0) + 1;
    const attempts = SNMP_COMMUNITIES.flatMap((community) => ([1, 0] as const).map((version) => ({ community, version })));
    const v3 = snmpV3Discovery(id);
    const [v3x, ...xs] = await Promise.all([
        exchange(ip, port, v3, timeout),
        ...attempts.map((a, i) => exchange(ip, port, snmpGetRequest(a.version, a.community, id + i + 1), timeout)),
    ]);

    const engine = v3x.replies.map(parseSnmpV3Report).find(Boolean) ?? null;
    const accepted = attempts
        .map((a, i) => ({ ...a, x: xs[i], res: xs[i].replies.map(parseSnmpResponse).find(Boolean) ?? null }))
        .filter((a) => a.res);
    if (!engine && accepted.length === 0) return null;

    const forensics = [`UDP ${port} answered SNMP requests`];
    const issues: { text: string; severity: Severity; fix: string }[] = [];
    const first = accepted[0]?.res;
    const descr = accepted.map((a) => a.res?.descr).find(Boolean);
    const name = accepted.map((a) => a.res?.name).find(Boolean);

    for (const a of accepted) {
        const label = `SNMP ${a.version === 1 ? 'v2c' : 'v1'} GetRequest with community "${a.community}"`;
        forensics.push(evidence(label, snmpGetRequest(a.version, a.community, 1).length, a.x));
    }
    if (accepted.length) {
        const list = Array.from(new Set(accepted.map((a) => `"${a.community}" (${accepted.filter((b) => b.community === a.community).map((b) => (b.version === 1 ? 'v2c' : 'v1')).join(', ')})`)));
        forensics.push(`Accepted community strings: ${list.join(', ')}`);
        if (descr) forensics.push(`sysDescr.0: ${descr}`);
        if (name) forensics.push(`sysName.0: ${name}`);
        const writeable = accepted.some((a) => a.community === 'private');
        issues.push({
            text: `SNMP accepts the default community ${accepted.map((a) => `"${a.community}"`).filter((v, i, s) => s.indexOf(v) === i).join(' and ')}: anyone can read device configuration, interfaces, routes and often ARP tables`,
            severity: writeable ? 'CRITICAL' : 'HIGH',
            fix: 'Disable SNMP v1 and v2c, or at least change the community strings and bind them to an ACL of management hosts. Move to SNMPv3 with authPriv (SHA and AES) and block UDP 161 at the internet edge.',
        });
        if (writeable) forensics.push('Logic: "private" is the factory default read-write community on many devices. Write access was not tested.');
    }
    if (engine) {
        forensics.push(evidence('SNMPv3 engine discovery (no credentials)', v3.length, v3x));
        forensics.push(`SNMPv3 engine ID ${engine.engineId}${engine.vendor ? ` (${engine.vendor})` : ''}${engine.mac ? `, MAC ${engine.mac}` : ''}${engine.address ? `, address ${engine.address}` : ''}, ${engine.boots} reboots, up ${uptime(engine.time)}`);
        issues.push({
            text: `SNMP agent reachable${engine.vendor ? `: engine ID identifies ${engine.vendor}` : ''}, and reveals reboot count and uptime without credentials`,
            severity: 'MEDIUM',
            fix: 'Restrict UDP 161 to management networks. SNMPv3 discovery cannot be turned off, so the port itself must be filtered.',
        });
    }

    const vendor = engine?.vendor;
    const version = accepted.length
        ? (accepted.some((a) => a.version === 0) ? 'v1/v2c' : 'v2c') + (engine ? ', v3' : '')
        : 'v3';
    return {
        ip, port, protocol: 'udp',
        service: 'SNMP',
        version,
        banner: (descr || (vendor ? `SNMPv3 agent, ${vendor}` : 'SNMPv3 agent')).slice(0, 300),
        severity: worst(...issues.map((i) => i.severity)),
        description: `Simple Network Management Protocol agent${vendor ? ` (${vendor})` : ''}${name ? `, sysName ${name}` : ''}${first ? '. Answers with a default community string' : ''}`,
        vulnerability: issues.map((i) => i.text).join('; '),
        remediation: issues.map((i) => i.fix).join(' '),
        forensics: forensics.join('\n'),
    };
}

/* ------------------------------------------------------------------ DNS */

export function dnsQuery(id: number, name: string, type: number, qclass: number, recursion: boolean): Buffer {
    const labels = name.split('.').filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(recursion ? 0x0100 : 0, 2);
    header.writeUInt16BE(1, 4);
    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(type, 0);
    tail.writeUInt16BE(qclass, 2);
    return Buffer.concat([header, ...labels, Buffer.from([0]), tail]);
}

function skipName(buf: Buffer, i: number): number {
    for (let guard = 0; guard < 128 && i < buf.length; guard++) {
        const b = buf[i];
        if ((b & 0xc0) === 0xc0) return i + 2;
        if (b === 0) return i + 1;
        i += b + 1;
    }
    throw new Error('bad DNS name');
}

export interface DnsReply { id: number; ra: boolean; rcode: number; answers: { type: number; data: Buffer }[] }

export function parseDnsReply(buf: Buffer): DnsReply | null {
    try {
        if (buf.length < 12) return null;
        const flags = buf.readUInt16BE(2);
        if (!(flags & 0x8000)) return null;
        let i = 12;
        for (let q = buf.readUInt16BE(4); q > 0; q--) i = skipName(buf, i) + 4;
        const answers: DnsReply['answers'] = [];
        for (let a = buf.readUInt16BE(6); a > 0 && i < buf.length; a--) {
            i = skipName(buf, i);
            const type = buf.readUInt16BE(i);
            const len = buf.readUInt16BE(i + 8);
            answers.push({ type, data: buf.subarray(i + 10, i + 10 + len) });
            i += 10 + len;
        }
        return { id: buf.readUInt16BE(0), ra: !!(flags & 0x0080), rcode: flags & 0x0f, answers };
    } catch {
        return null;
    }
}

function txt(data: Buffer): string {
    const parts: string[] = [];
    for (let i = 0; i < data.length; i += data[i] + 1) parts.push(data.subarray(i + 1, i + 1 + data[i]).toString('latin1'));
    return text(parts.join(''), 200);
}

export async function probeDns(ip: string, port = 53, timeout = 2000): Promise<UdpFinding | null> {
    const id = randomBytes(2).readUInt16BE(0);
    const versionQ = dnsQuery(id, 'version.bind', 16, 3, false);
    const recurseQ = dnsQuery(id ^ 0xffff, 'example.com', 1, 1, true);
    const [vx, rx] = await Promise.all([exchange(ip, port, versionQ, timeout), exchange(ip, port, recurseQ, timeout)]);
    const vr = vx.replies.map(parseDnsReply).find((r) => r?.id === id) ?? null;
    const rr = rx.replies.map(parseDnsReply).find((r) => r?.id === (id ^ 0xffff)) ?? null;
    if (!vr && !rr) return null;

    const forensics = [`UDP ${port} answered DNS queries`];
    const issues: { text: string; severity: Severity; fix: string }[] = [];
    const versionText = vr?.answers.find((a) => a.type === 16) ? txt(vr.answers.find((a) => a.type === 16)!.data) : '';
    if (vr) {
        forensics.push(evidence('CHAOS TXT query for version.bind', versionQ.length, vx));
        forensics.push(versionText ? `version.bind: "${versionText}"` : `version.bind not disclosed (rcode ${vr.rcode})`);
        if (versionText) {
            issues.push({ text: `DNS server discloses its version: "${versionText}"`, severity: 'LOW', fix: 'Hide the version string, for example "version none;" in BIND options or "hide-version: yes" in Unbound.' });
        }
    }
    const open = !!rr && rr.ra && rr.rcode === 0 && rr.answers.length > 0;
    if (rr) {
        forensics.push(evidence('recursive A query for example.com', recurseQ.length, rx));
        forensics.push(open ? `Recursion available and an answer was returned (${rr.answers.length} records)` : `No recursion for outside clients (RA ${rr.ra ? 'set' : 'clear'}, rcode ${rr.rcode})`);
    }
    if (open) {
        issues.push({
            text: 'Open recursive resolver: answers recursive queries from anyone, which enables DNS amplification attacks and cache poisoning attempts',
            severity: 'HIGH',
            fix: 'Restrict recursion to internal clients ("allow-recursion { trusted; };" in BIND, "access-control" in Unbound, or disable recursion on authoritative servers).',
        });
    }
    return {
        ip, port, protocol: 'udp',
        service: 'DNS',
        version: versionText.match(/\d+\.\d+(\.\d+)?/)?.[0],
        banner: versionText || undefined,
        severity: worst('INFO', ...issues.map((i) => i.severity)),
        description: open ? 'DNS server that resolves names for anyone' : 'DNS server answering on UDP',
        vulnerability: issues.map((i) => i.text).join('; ') || undefined,
        remediation: issues.map((i) => i.fix).join(' ') || undefined,
        forensics: forensics.join('\n'),
    };
}

/* ------------------------------------------------------------------ text based: SIP, SSDP */

function header(reply: string, name: string): string | undefined {
    return reply.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'))?.[1]?.trim();
}

export async function probeSip(ip: string, port = 5060, timeout = 2000): Promise<UdpFinding | null> {
    const tag = randomBytes(4).toString('hex');
    const request = Buffer.from([
        `OPTIONS sip:nm@${ip} SIP/2.0`,
        `Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK${tag};rport`,
        'Max-Forwards: 70',
        `From: <sip:nm@nm>;tag=${tag}`,
        `To: <sip:nm@${ip}>`,
        `Call-ID: ${tag}@nm`,
        'CSeq: 1 OPTIONS',
        'Accept: application/sdp',
        'Content-Length: 0',
        '', '',
    ].join('\r\n'));
    const x = await exchange(ip, port, request, timeout);
    const reply = x.replies.map((r) => r.toString('latin1')).find((r) => r.startsWith('SIP/2.0'));
    if (!reply) return null;
    const status = text(reply.split('\r\n')[0], 80);
    const agent = text(header(reply, 'Server') || header(reply, 'User-Agent') || '', 150);
    const allow = text(header(reply, 'Allow') || '', 150);
    return {
        ip, port, protocol: 'udp',
        service: 'SIP',
        version: agent.match(/\d+\.\d+(\.\d+)?/)?.[0],
        banner: agent || status,
        severity: 'MEDIUM',
        description: 'Session Initiation Protocol (VoIP) endpoint answering on UDP',
        vulnerability: `SIP endpoint answers anonymous OPTIONS requests${agent ? ` and identifies as "${agent}"` : ''}. Exposed PBXs are scanned constantly for extension enumeration and toll fraud`,
        remediation: 'Allow SIP only from your carrier and remote sites, set strong extension passwords, enable fail2ban or an equivalent, and hide the User-Agent string.',
        forensics: [
            `UDP ${port} answered a SIP OPTIONS request`,
            evidence('SIP OPTIONS', request.length, x),
            `Status: ${status}`,
            agent && `Server: ${agent}`,
            allow && `Allowed methods: ${allow}`,
        ].filter(Boolean).join('\n'),
    };
}

export const SSDP_SEARCH = Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n');

export async function probeSsdp(ip: string, port = 1900, timeout = 2000): Promise<UdpFinding | null> {
    const x = await exchange(ip, port, SSDP_SEARCH, timeout, 800);
    const replies = x.replies.map((r) => r.toString('latin1')).filter((r) => /^HTTP\/1\.1 200/i.test(r));
    if (replies.length === 0) return null;
    const server = text(header(replies[0], 'Server') || '', 150);
    const location = text(header(replies[0], 'Location') || '', 200);
    const types = Array.from(new Set(replies.map((r) => text(header(r, 'ST') || '', 100)).filter(Boolean)));
    return {
        ip, port, protocol: 'udp',
        service: 'SSDP/UPnP',
        version: server.match(/UPnP\/(\d\.\d)/i)?.[1],
        banner: server || undefined,
        severity: 'HIGH',
        description: 'UPnP discovery service answering from outside the local network',
        vulnerability: 'SSDP answers unicast M-SEARCH requests: the device can be abused for reflection DDoS and exposes its UPnP description, which may allow port mapping changes',
        remediation: 'Disable UPnP on the internet facing interface of this device, and block UDP 1900 inbound at the edge.',
        forensics: [
            `UDP ${port} answered an SSDP M-SEARCH request`,
            evidence('SSDP M-SEARCH ssdp:all', SSDP_SEARCH.length, x),
            server && `Server: ${server}`,
            location && `Device description: ${location}`,
            types.length > 0 && `Advertised types: ${types.slice(0, 8).join(', ')}`,
        ].filter(Boolean).join('\n'),
    };
}

/* ------------------------------------------------------------------ memcached */

export const MEMCACHED_VERSION = Buffer.concat([Buffer.from([0, 1, 0, 0, 0, 1, 0, 0]), Buffer.from('version\r\n')]);

export async function probeMemcached(ip: string, port = 11211, timeout = 2000): Promise<UdpFinding | null> {
    const x = await exchange(ip, port, MEMCACHED_VERSION, timeout);
    const reply = x.replies.find((r) => r.length > 8 && r.subarray(8).toString('latin1').startsWith('VERSION'));
    if (!reply) return null;
    const line = text(reply.subarray(8), 80);
    const version = line.replace(/^VERSION\s*/, '');
    return {
        ip, port, protocol: 'udp',
        service: 'memcached',
        version: version || undefined,
        banner: line,
        severity: 'CRITICAL',
        description: 'memcached with its UDP listener enabled and reachable',
        vulnerability: 'CVE-2018-1000115: memcached over UDP can amplify traffic up to 50,000x and was behind the largest recorded DDoS attacks. The cache itself is also readable without authentication',
        remediation: 'Start memcached with "-U 0" to disable UDP (the default since 1.5.6), bind it to localhost or a private interface with "-l", and block UDP and TCP 11211 at the edge.',
        forensics: [`UDP ${port} answered a memcached version command`, evidence('memcached "version" over UDP', MEMCACHED_VERSION.length, x), `Reply: ${line}`].join('\n'),
    };
}

/* ------------------------------------------------------------------ all probes */

export const UDP_PROBES = [
    { port: 53, service: 'DNS', run: probeDns },
    { port: 123, service: 'NTP', run: probeNtp },
    { port: 161, service: 'SNMP', run: probeSnmp },
    { port: 1900, service: 'SSDP', run: probeSsdp },
    { port: 5060, service: 'SIP', run: probeSip },
    { port: 11211, service: 'memcached', run: probeMemcached },
];
export const UDP_PROBE_PORTS = UDP_PROBES.map((p) => p.port);

/** Runs every UDP probe against one host. Ports that stay silent produce no finding. */
export async function probeUdp(ip: string, timeout = 2000): Promise<UdpFinding[]> {
    const results = await Promise.all(UDP_PROBES.map((p) => p.run(ip, p.port, timeout).catch(() => null)));
    return results.filter((r): r is UdpFinding => r !== null);
}
