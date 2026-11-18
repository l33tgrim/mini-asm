import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import { groupFindings, type GroupableFinding } from '../lib/group-findings';
import { checkPath, describePathCheck } from '../lib/scanner';

const f = (ip: string, over: Partial<GroupableFinding> = {}): GroupableFinding => ({
    id: `${ip}-${over.port ?? 53}-${over.protocol ?? 'udp'}`, ip, port: 53, protocol: 'udp', service: 'DNS', severity: 'HIGH',
    description: 'DNS server that resolves names for anyone', vulnerability: 'Open recursive resolver', remediation: 'Restrict recursion.',
    updatedAt: '2026-11-18T09:00:00Z', ...over,
});

test('one group per issue, hosts listed inside in address order', () => {
    const groups = groupFindings([
        f('196.13.107.10'), f('196.13.107.2'), f('196.13.107.1', { updatedAt: '2026-11-18T11:30:00Z' }),
        f('196.13.107.121', { port: 161, service: 'SNMP', severity: 'CRITICAL', vulnerability: 'Default community "private"' }),
        f('196.13.107.5', { port: 53, protocol: 'tcp', severity: 'LOW', vulnerability: null }),
    ]);
    assert.equal(groups.length, 3);
    assert.equal(groups[0].service, 'SNMP', 'worst severity first');
    const dns = groups[1];
    assert.deepEqual(dns.findings.map((x) => x.ip), ['196.13.107.1', '196.13.107.2', '196.13.107.10']);
    assert.deepEqual(dns.issues, [{ text: 'Open recursive resolver', hosts: 3 }]);
    assert.equal(dns.lastSeen, '2026-11-18T11:30:00Z');
    assert.equal(groups[2].protocol, 'tcp', 'tcp and udp on the same port stay apart');
});

test('issues that only some hosts have are counted', () => {
    const [g] = groupFindings([
        f('10.0.0.1', { vulnerability: 'A; B' }), f('10.0.0.2', { vulnerability: 'A' }), f('10.0.0.3', { vulnerability: 'A; A' }),
    ]);
    assert.deepEqual(g.issues, [{ text: 'A', hosts: 3 }, { text: 'B', hosts: 1 }]);
});

test('the path check flags ports the control address answers', async () => {
    const server = net.createServer((s) => s.destroy());
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const open = (server.address() as net.AddressInfo).port;
    try {
        const check = await checkPath([open, 1], false, '127.0.0.1');
        assert.deepEqual(check, { tcp: [open], udp: [] });
        assert.match(describePathCheck(check)!, new RegExp(`Skipped TCP ${open}: the network`));
        assert.equal(describePathCheck({ tcp: [], udp: [] }), null);
        assert.match(describePathCheck({ tcp: [], udp: [53, 123] })!, /Skipped UDP 53, 123/);
    } finally {
        server.close();
    }
});
