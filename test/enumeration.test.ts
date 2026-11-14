import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'dns';
import { resolveDomain } from '../lib/scanner';
import { networkOwner } from '../lib/discovery';

// A small fake internet: DNS answers and the two public sources are stubbed so
// the whole enumeration flow can be exercised offline. The addresses are in
// TEST-NET space, which the scanner refuses to connect to.
const A: Record<string, string[]> = {
    'corp.test': ['192.0.2.10'],
    'www.corp.test': ['192.0.2.10'],
    'pay-uat.corp.test': ['192.0.2.20'],
    'pay-dr.corp.test': ['192.0.2.21'],
    'mft.corp.test': ['192.0.2.30'],
    'mx1.corp.test': ['192.0.2.40'],
};
const CNAME: Record<string, string[]> = {
    'mft.corp.test': ['corp-mft.azurewebsites.net'],
    'old-shop.corp.test': ['corp-shop.herokuapp.com'],
};
const notFound = () => Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));

test('domain enumeration combines DNS, certificate logs, patterns and ownership', async () => {
    const p = dns.promises;
    mock.method(p, 'resolve4', (name: string) => (A[name] ? Promise.resolve(A[name]) : notFound()));
    mock.method(p, 'resolve6', notFound);
    mock.method(p, 'resolveCname', (name: string) => (CNAME[name] ? Promise.resolve(CNAME[name]) : notFound()));
    mock.method(p, 'resolveNs', () => Promise.resolve(['ns1.dnsprovider.net.']));
    mock.method(p, 'resolveMx', () => Promise.resolve([{ exchange: 'mx1.corp.test', priority: 10 }]));
    mock.method(p, 'resolveSrv', notFound);
    mock.method(p, 'resolveTxt', (name: string) => {
        if (name === 'corp.test') return Promise.resolve([['v=spf1 ip4:192.0.2.0/24 include:spf.protection.outlook.com -all'], ['MS=ms123456']]);
        if (name === '_dmarc.corp.test') return Promise.resolve([['v=DMARC1; p=reject']]);
        if (name === 'selector1._domainkey.corp.test') return Promise.resolve([['v=DKIM1; p=abc']]);
        return notFound();
    });
    mock.method(globalThis, 'fetch', async (url: string | URL) => {
        const u = String(url);
        if (u.includes('crt.sh')) {
            return Response.json([
                { name_value: 'pay-uat.corp.test\n*.corp.test' },
                { name_value: 'mft.corp.test' },
                { name_value: 'old-shop.corp.test' },
                { name_value: 'evil.other.test' },
            ]);
        }
        if (u.includes('rdap.org')) {
            return Response.json({
                name: 'CORP-NET', country: 'ZA', cidr0_cidrs: [{ v4prefix: '192.0.2.0', length: 24 }],
                entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Corp Holdings']]] }],
            });
        }
        return new Response('', { status: 404 });
    });

    const r = await resolveDomain('corp.test');
    const has = (needle: string) => r.details.some((d) => d.includes(needle));

    assert.deepEqual(r.subdomains, ['mft.corp.test', 'mx1.corp.test', 'pay-dr.corp.test', 'pay-uat.corp.test', 'www.corp.test']);
    assert.ok(has('Subdomain [certificate log]: mft.corp.test'), 'certificate log names are resolved');
    assert.ok(has('Subdomain [naming pattern]: pay-dr.corp.test'), 'siblings are guessed from the pattern');
    assert.ok(has('Subdomain [dns record]: mx1.corp.test'), 'in-scope mail hosts join the surface');
    assert.deepEqual(r.staleNames, ['old-shop.corp.test']);
    assert.ok(has('Alias: old-shop.corp.test -> corp-shop.herokuapp.com [Heroku]'), 'stale names keep their alias for takeover checks');
    assert.ok(has('Alias: mft.corp.test -> corp-mft.azurewebsites.net [Azure App Service]'));
    assert.ok(has('SaaS in use: Microsoft 365'));
    assert.ok(has('Third-party sender: spf.protection.outlook.com [Microsoft 365]'));
    assert.ok(has('Declared mail range: 192.0.2.0/24'));
    assert.ok(has('DKIM selectors found: selector1'));
    assert.deepEqual(await networkOwner('192.0.2.10'), { name: 'Corp Holdings / CORP-NET', range: '192.0.2.0/24', country: 'ZA' });
    assert.ok(r.relatedDomains.includes('dnsprovider.net'));
    assert.ok(!r.subdomains.some((h) => h.includes('other.test')), 'names outside the domain never join the scan');
    assert.equal(r.hostMap['192.0.2.20']?.[0], 'pay-uat.corp.test');

    mock.restoreAll();
});
