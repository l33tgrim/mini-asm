import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'dgram';
import { DEFAULT_TCP_PORTS, MAX_PORTS_PER_HOST, parsePortSpec, portMeta, PortSpecError } from '../lib/ports';
import {
    berDecode, exchange, parseMonlist, parseNtpTime, parseNtpVariables, parseSnmpResponse, parseSnmpV3Report,
    probeDns, probeMemcached, probeNtp, probeSip, probeSnmp, probeSsdp, snmpGetRequest, snmpV3Discovery,
} from '../lib/udp';
import { serviceFromBanner } from '../lib/scanner';

/* ---------------------------------------------------------------- port specs */

test('empty spec means the default list', () => {
    assert.deepEqual(parsePortSpec(''), [...DEFAULT_TCP_PORTS].sort((a, b) => a - b));
    assert.deepEqual(parsePortSpec(null), parsePortSpec('default'));
});

test('ranges, single ports and presets combine, sorted and unique', () => {
    assert.deepEqual(parsePortSpec('8080, 22 8000-8003;22'), [22, 8000, 8001, 8002, 8003, 8080]);
    const remote = parsePortSpec('remote-access');
    for (const p of [22, 23, 3389, 5900, 5903, 5985, 5938]) assert.ok(remote.includes(p), `remote-access has ${p}`);
    assert.equal(parsePortSpec('well-known').length, 1024);
    const mixed = parsePortSpec('databases, 10443');
    assert.ok(mixed.includes(5432) && mixed.includes(10443));
});

test('bad specs explain what is wrong', () => {
    assert.throws(() => parsePortSpec('0'), PortSpecError);
    assert.throws(() => parsePortSpec('65536'), /between 1 and 65535/);
    assert.throws(() => parsePortSpec('900-100'), /backwards/);
    assert.throws(() => parsePortSpec('ssh'), /preset name/);
    assert.throws(() => parsePortSpec(`1-${MAX_PORTS_PER_HOST + 1}`), /Narrow the range/);
    assert.throws(() => parsePortSpec('1-3000, 10000-13000'), /Narrow the range/);
});

test('unlisted ports get a generic entry, known extras get a name', () => {
    assert.equal(portMeta(22).service, 'SSH');
    assert.equal(portMeta(502).service, 'Modbus');
    assert.equal(portMeta(5938).service, 'TeamViewer');
    assert.deepEqual(portMeta(31337).service, 'Unknown');
});

test('banners name services on unknown ports', () => {
    assert.equal(serviceFromBanner('SSH-2.0-OpenSSH_9.6'), 'SSH');
    assert.equal(serviceFromBanner('HTTP/1.1 400 Bad Request'), 'HTTP');
    assert.equal(serviceFromBanner('RFB 003.008\n'), 'VNC');
    assert.equal(serviceFromBanner('220 ProFTPD Server ready (ftp)'), 'FTP');
    assert.equal(serviceFromBanner(null), null);
});

/* ---------------------------------------------------------------- BER helpers for fake agents */

const len = (n: number) => (n < 0x80 ? Buffer.from([n]) : Buffer.from([0x81, n]));
const tlv = (tag: number, ...parts: Buffer[]) => { const b = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(b.length), b]); };
const int = (n: number) => { const out: number[] = []; do { out.unshift(n & 0xff); n = Math.floor(n / 256); } while (n > 0); if (out[0] & 0x80) out.unshift(0); return tlv(0x02, Buffer.from(out)); };
const str = (s: string | Buffer) => tlv(0x04, Buffer.isBuffer(s) ? s : Buffer.from(s));

function snmpResponse(request: Buffer, values: string[]): Buffer {
    const msg = berDecode(request)[0];
    const pdu = msg.children![2];
    const binds = pdu.children![3].children!.map((vb, i) => tlv(0x30, Buffer.concat([Buffer.from([0x06, vb.children![0].value.length]), vb.children![0].value]), str(values[i] ?? '')));
    const resp = tlv(0xa2, int(berToNum(pdu.children![0].value)), int(0), int(0), tlv(0x30, ...binds));
    return tlv(0x30, int(berToNum(msg.children![0].value)), str(msg.children![1].value), resp);
}
const berToNum = (b: Buffer) => b.reduce((n, x) => n * 256 + x, 0);

function snmpV3Report(engineId: Buffer, boots: number, time: number): Buffer {
    const header = tlv(0x30, int(1), int(65507), str(Buffer.from([0])), int(3));
    const usm = tlv(0x30, str(engineId), int(boots), int(time), str(''), str(''), str(''));
    const report = tlv(0xa8, int(1), int(0), int(0), tlv(0x30));
    return tlv(0x30, int(3), header, str(usm), tlv(0x30, str(engineId), str(''), report));
}

/* ---------------------------------------------------------------- packet parsers */

test('SNMP GetRequest round-trips through the decoder', () => {
    const req = snmpGetRequest(1, 'public', 4242);
    const msg = berDecode(req)[0];
    assert.equal(msg.tag, 0x30);
    assert.equal(msg.children![1].value.toString(), 'public');
    assert.equal(msg.children![2].tag, 0xa0);
    const parsed = parseSnmpResponse(snmpResponse(req, ['Cisco IOS Software, C2960 Version 15.0(2)SE', 'core-sw1']));
    assert.deepEqual(parsed, { descr: 'Cisco IOS Software, C2960 Version 15.0(2)SE', name: 'core-sw1' });
    assert.equal(parseSnmpResponse(req), null, 'a request is not a response');
    assert.equal(parseSnmpResponse(Buffer.from([0x30, 0x40, 0x02])), null, 'truncated input is rejected');
});

test('SNMPv3 report gives vendor, MAC, reboots and uptime', () => {
    berDecode(snmpV3Discovery(7)); // well formed
    const engineId = Buffer.from('8000000903' + '0011223344aa', 'hex'); // Cisco, MAC format
    const e = parseSnmpV3Report(snmpV3Report(engineId, 12, 90061));
    assert.equal(e?.vendor, 'Cisco');
    assert.equal(e?.mac, '00:11:22:33:44:aa');
    assert.equal(e?.boots, 12);
    assert.equal(e?.time, 90061);
});

test('NTP replies are parsed', () => {
    const reply = Buffer.alloc(48);
    reply[0] = 0x24; reply[1] = 1; reply.write('GPS', 12);
    reply.writeUInt32BE(2208988800 + 1_800_000_000, 40);
    assert.deepEqual(parseNtpTime(reply), { version: 4, stratum: 1, refid: 'GPS', serverTime: '2027-01-15T08:00:00.000Z' });

    const body = Buffer.from('version="ntpd 4.2.6p5@1.2349-o Fri Jul 22 2016", processor="x86_64", system="Linux/3.10.0", stratum=2');
    const head = Buffer.alloc(12); head[0] = 0x16; head[1] = 0x82; head.writeUInt16BE(body.length, 10);
    assert.equal(parseNtpVariables([Buffer.concat([head, body])])?.system, 'Linux/3.10.0');

    const mon = Buffer.alloc(8); mon[0] = 0x97; mon[3] = 0x2a; mon.writeUInt16BE(6, 4);
    assert.deepEqual(parseMonlist([mon]), { ok: true, items: 6 });
    mon[4] = 0x40; // error code 4: request refused
    assert.equal(parseMonlist([mon]).ok, false);
});

/* ---------------------------------------------------------------- probes against local fake services */

async function fakeServer(handler: (msg: Buffer) => Buffer | Buffer[] | null): Promise<{ port: number; close: () => void }> {
    const s = dgram.createSocket('udp4');
    s.on('message', (msg, rinfo) => {
        const out = handler(msg);
        for (const b of out ? (Array.isArray(out) ? out : [out]) : []) s.send(b, rinfo.port, rinfo.address);
    });
    await new Promise<void>((r) => s.bind(0, '127.0.0.1', r));
    return { port: s.address().port, close: () => s.close() };
}

test('a UDP port with nothing listening reports refused', async () => {
    const s = await fakeServer(() => null);
    const { port } = s;
    s.close();
    const x = await exchange('127.0.0.1', port, Buffer.from('x'), 1000);
    assert.equal(x.replies.length, 0);
    assert.equal(x.refused, true);
});

test('NTP probe reports version, OS and monlist with evidence', async () => {
    const s = await fakeServer((msg) => {
        const mode = msg[0] & 7;
        if (mode === 3) { const r = Buffer.alloc(48); r[0] = 0x1c; r[1] = 2; Buffer.from([10, 0, 0, 1]).copy(r, 12); return r; }
        if (mode === 6) {
            const body = Buffer.from('version="ntpd 4.2.6p5@1.2349-o", system="Linux/3.10.0", processor="x86_64"');
            const h = Buffer.alloc(12); h[0] = 0x16; h[1] = 0x82; h.writeUInt16BE(body.length, 10);
            return Buffer.concat([h, body]);
        }
        if (mode === 7) { const r = Buffer.alloc(440); r[0] = 0x97; r[3] = 0x2a; r.writeUInt16BE(6, 4); return [r, r]; }
        return null;
    });
    try {
        const f = await probeNtp('127.0.0.1', s.port, 1500);
        assert.ok(f);
        assert.equal(f.protocol, 'udp');
        assert.equal(f.service, 'NTP');
        assert.equal(f.version, '4.2.6p5');
        assert.equal(f.severity, 'HIGH');
        assert.match(f.vulnerability!, /CVE-2013-5211/);
        assert.match(f.vulnerability!, /older than 4\.2\.8/);
        assert.match(f.forensics!, /stratum 2, reference 10\.0\.0\.1/);
        assert.match(f.forensics!, /Operating system reported by ntpd: Linux\/3\.10\.0/);
        assert.match(f.forensics!, /monlist\) \(48 bytes\), got 2 replies totalling 880 bytes/);
        assert.match(f.remediation!, /disable monitor/);
    } finally {
        s.close();
    }
});

test('NTP that only serves time is low severity', async () => {
    const s = await fakeServer((msg) => {
        if ((msg[0] & 7) !== 3) return null;
        const r = Buffer.alloc(48); r[0] = 0x24; r[1] = 1; r.write('PPS', 12); return r;
    });
    try {
        const f = await probeNtp('127.0.0.1', s.port, 800);
        assert.equal(f?.severity, 'LOW');
        assert.equal(f?.vulnerability, undefined);
    } finally {
        s.close();
    }
});

test('SNMP probe flags default communities and reads sysDescr and engine ID', async () => {
    const engineId = Buffer.from('80001f8803' + 'deadbeef0001', 'hex'); // net-snmp, MAC
    const s = await fakeServer((msg) => {
        const m = berDecode(msg)[0];
        const version = berToNum(m.children![0].value);
        if (version === 3) return snmpV3Report(engineId, 3, 3600);
        if (m.children![1].value.toString() !== 'public') return null; // wrong community: agents stay silent
        return snmpResponse(msg, ['Linux fw01 5.15.0-91-generic x86_64', 'fw01']);
    });
    try {
        const f = await probeSnmp('127.0.0.1', s.port, 1000);
        assert.ok(f);
        assert.equal(f.service, 'SNMP');
        assert.equal(f.severity, 'HIGH');
        assert.equal(f.version, 'v1/v2c, v3');
        assert.equal(f.banner, 'Linux fw01 5.15.0-91-generic x86_64');
        assert.match(f.forensics!, /Accepted community strings: "public" \(v2c, v1\)/);
        assert.match(f.forensics!, /engine ID 80001f8803deadbeef0001 \(net-snmp\), MAC de:ad:be:ef:00:01, 3 reboots, up 1h 0m/);
        assert.match(f.remediation!, /SNMPv3 with authPriv/);
    } finally {
        s.close();
    }
});

test('DNS probe spots an open resolver and the version string', async () => {
    const s = await fakeServer((msg) => {
        const id = msg.readUInt16BE(0);
        const recursion = (msg.readUInt16BE(2) & 0x0100) !== 0;
        const q = msg.subarray(12);
        const head = Buffer.alloc(12);
        head.writeUInt16BE(id, 0);
        head.writeUInt16BE(0x8000 | (recursion ? 0x0180 : 0), 2);
        head.writeUInt16BE(1, 4);
        head.writeUInt16BE(1, 6);
        const rr = recursion
            ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14])
            : Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 16, 0, 3, 0, 0, 0, 0, 0, 14, 13]), Buffer.from('9.11.4-P2-RH')]);
        return Buffer.concat([head, q, rr]);
    });
    try {
        const f = await probeDns('127.0.0.1', s.port, 1000);
        assert.equal(f?.severity, 'HIGH');
        assert.equal(f?.version, '9.11.4');
        assert.match(f!.vulnerability!, /Open recursive resolver/);
    } finally {
        s.close();
    }
});

test('memcached, SSDP and SIP probes read what the service says', async () => {
    const mem = await fakeServer((msg) => Buffer.concat([msg.subarray(0, 8), Buffer.from('VERSION 1.4.15\r\n')]));
    const ssdp = await fakeServer(() => Buffer.from('HTTP/1.1 200 OK\r\nSERVER: Linux/2.6 UPnP/1.0 MiniUPnPd/1.9\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n'));
    const sip = await fakeServer(() => Buffer.from('SIP/2.0 200 OK\r\nServer: Asterisk PBX 16.2.1\r\nAllow: INVITE, ACK, OPTIONS\r\n\r\n'));
    try {
        const [m, u, v] = await Promise.all([
            probeMemcached('127.0.0.1', mem.port, 800),
            probeSsdp('127.0.0.1', ssdp.port, 800),
            probeSip('127.0.0.1', sip.port, 800),
        ]);
        assert.equal(m?.severity, 'CRITICAL');
        assert.equal(m?.version, '1.4.15');
        assert.equal(u?.version, '1.0');
        assert.match(u!.forensics!, /rootDesc\.xml/);
        assert.equal(v?.version, '16.2.1');
        assert.equal(v?.banner, 'Asterisk PBX 16.2.1');
    } finally {
        mem.close(); ssdp.close(); sip.close();
    }
});

test('silent services produce no finding', async () => {
    const s = await fakeServer(() => null);
    try {
        assert.equal(await probeSnmp('127.0.0.1', s.port, 300), null);
        assert.equal(await probeNtp('127.0.0.1', s.port, 300), null);
    } finally {
        s.close();
    }
});
