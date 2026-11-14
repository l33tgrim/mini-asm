import test from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint, assess, olderThan } from '../lib/engine/scenarios/web-tech-vulns';
import { EXPOSURE_CHECKS } from '../lib/engine/scenarios/web-exposure-scan';
import { ALL_SCENARIOS } from '../lib/engine/scenarios';
import { ALL_PLAYBOOKS } from '../lib/engine/playbooks';

test('version comparison', () => {
    assert.equal(olderThan('2.4.49', '2.4.51'), true);
    assert.equal(olderThan('2.4.51', '2.4.51'), false);
    assert.equal(olderThan('10.0', '10.0'), false);
    assert.equal(olderThan('8.5', '10.0'), true);
    assert.equal(olderThan('3.10.0', '3.5.0'), false);
});

test('fingerprint reads versions from headers and markup', () => {
    const hits = fingerprint(
        { server: 'Apache/2.4.49 (Unix) OpenSSL/1.1.1k', 'x-powered-by': 'PHP/7.4.3' },
        '<meta name="generator" content="WordPress 6.1.1"><script src="/js/jquery-1.12.4.min.js"></script>',
    );
    const map = Object.fromEntries(hits.map((h) => [h.product, h.version]));
    assert.equal(map['Apache httpd'], '2.4.49');
    assert.equal(map['OpenSSL'], '1.1.1');
    assert.equal(map['PHP'], '7.4.3');
    assert.equal(map['WordPress'], '6.1.1');
    assert.equal(map['jQuery'], '1.12.4');
});

test('old versions are flagged and current ones are not', () => {
    const flagged = assess([
        { product: 'Apache httpd', version: '2.4.49' },
        { product: 'jQuery', version: '1.12.4' },
        { product: 'nginx', version: '1.27.2' },
        { product: 'PHP', version: '8.3.1' },
    ]).map((f) => f.hit.product);
    assert.deepEqual(flagged, ['Apache httpd', 'jQuery']);
});

test('exposure signatures match real formats and ignore ordinary pages', () => {
    const sig = (path: string) => EXPOSURE_CHECKS.find((c) => c.path === path)!.signature;
    const page = '<!doctype html><html><head><title>Welcome</title></head><body>Hello</body></html>';
    assert.ok(sig('/.git/HEAD').test('ref: refs/heads/main\n'));
    assert.ok(sig('/.env').test('APP_ENV=production\nDB_PASSWORD=x\n'));
    assert.ok(sig('/swagger.json').test('{"openapi":"3.0.1","paths":{}}'));
    for (const c of EXPOSURE_CHECKS) assert.equal(c.signature.test(page), false, c.path);
});

test('new scenarios are registered and every playbook step exists', () => {
    const ids = new Set(ALL_SCENARIOS.map((s) => s.id));
    assert.ok(ids.has('web-exposure-scan') && ids.has('web-tech-vulns'));
    assert.equal(ids.size, ALL_SCENARIOS.length);
    for (const p of ALL_PLAYBOOKS) for (const id of p.scenarioIds) assert.ok(ids.has(id), `${p.id}: ${id}`);
});

test('scenarios run end to end against a mocked site', async () => {
    const { webExposureScan } = await import('../lib/engine/scenarios/web-exposure-scan');
    const { webTechVulns } = await import('../lib/engine/scenarios/web-tech-vulns');
    const pages: Record<string, string> = {
        '/': '<html><script src="/jquery-1.12.4.min.js"></script></html>',
        '/.git/HEAD': 'ref: refs/heads/main\n',
        '/.env': 'DB_PASSWORD=hunter2\nAPI_KEY=abc\n',
        '/robots.txt': 'User-agent: *\nDisallow: /admin-old/\n',
    };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request) => {
        const body = pages[new URL(String(input)).pathname];
        return new Response(body ?? 'not found', { status: body ? 200 : 404, headers: { server: 'nginx/1.18.0' } });
    }) as typeof fetch;
    try {
        const ctx = () => ({
            target: '8.8.8.8', mode: 'SAFE' as const, params: {}, log: () => {},
            state: { services: [{ ip: '8.8.8.8', port: 443, service: 'HTTPS' }] } as Record<string, unknown>,
        });
        const exposure = await webExposureScan.run(ctx() as never);
        const proven = exposure.filter((r) => r.outcome === 'PROVEN');
        assert.equal(proven.length, 2);
        assert.ok(exposure.some((r) => r.title.startsWith('robots.txt')));
        assert.ok(!JSON.stringify(exposure).includes('hunter2'), 'secret values must never reach the evidence');

        const tech = await webTechVulns.run(ctx() as never);
        const titles = tech.filter((r) => r.outcome === 'VULNERABLE').map((r) => r.title).join(' | ');
        assert.match(titles, /nginx 1\.18\.0/);
        assert.match(titles, /jQuery 1\.12\.4/);
    } finally {
        globalThis.fetch = realFetch;
    }
});
