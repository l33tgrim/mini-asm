import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSpf, patternCandidates, providerFor, registrableDomain, servicesFromTxt } from '../lib/discovery';

test('pattern candidates swap environment tokens and step numbers', () => {
    const out = patternCandidates('example.com', ['api-uat.example.com', 'web1.example.com']);
    assert.ok(out.includes('api-dev.example.com'));
    assert.ok(out.includes('api-prod.example.com'));
    assert.ok(out.includes('api.example.com'));
    assert.ok(out.includes('web2.example.com'));
    assert.ok(out.includes('dev.api-uat.example.com'));
    assert.ok(!out.includes('api-uat.example.com'), 'known names are not suggested again');
    assert.ok(out.every((h) => h.endsWith('.example.com')));
});

test('pattern candidates are capped', () => {
    const found = Array.from({ length: 200 }, (_, i) => `host${i}.example.com`);
    assert.ok(patternCandidates('example.com', found).length <= 400);
});

test('registrable domain handles two-part public suffixes', () => {
    assert.equal(registrableDomain('a.b.example.co.za'), 'example.co.za');
    assert.equal(registrableDomain('www.example.com'), 'example.com');
    assert.equal(registrableDomain('example.com.'), 'example.com');
});

test('providers are recognised from alias targets', () => {
    assert.equal(providerFor('d111.cloudfront.net'), 'AWS CloudFront');
    assert.equal(providerFor('app.azurewebsites.net.'), 'Azure App Service');
    assert.equal(providerFor('host.example.com'), null);
});

test('SPF parsing extracts includes and ranges', () => {
    const spf = parseSpf('v=spf1 ip4:196.1.2.0/24 include:spf.protection.outlook.com ~all');
    assert.deepEqual(spf.includes, ['spf.protection.outlook.com']);
    assert.deepEqual(spf.ranges, ['196.1.2.0/24']);
});

test('verification TXT records reveal services', () => {
    assert.deepEqual(servicesFromTxt(['MS=ms12345678', 'v=spf1 -all', 'atlassian-domain-verification=abc']).sort(), ['Atlassian', 'Microsoft 365']);
});
