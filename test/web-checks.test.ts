import test from 'node:test';
import assert from 'node:assert/strict';
import { certificateLifetimeIssues, cookieIssues, headerIssues, unsafeCsp } from '../lib/web-checks';
import { dsPublished } from '../lib/discovery';

const headers = (h: Record<string, string>, cookies: string[] = []) => ({
    get: (n: string) => h[n.toLowerCase()] ?? null,
    getSetCookie: () => cookies,
});
const texts = (issues: { text: string }[]) => issues.map((i) => i.text).join(' | ');

const good = {
    'strict-transport-security': 'max-age=31536000',
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    server: 'nginx',
};

test('a well configured https page has no issues', () => {
    assert.deepEqual(headerIssues('https', 200, headers(good, ['sid=1; Secure; HttpOnly'])), []);
});

test('https redirecting to http is flagged', () => {
    const issues = headerIssues('https', 301, headers({ ...good, location: 'http://example.com/' }));
    assert.match(texts(issues), /insecure address/);
    assert.equal(issues.find((i) => i.text.includes('insecure'))?.severity, 'MEDIUM');
    assert.doesNotMatch(texts(headerIssues('https', 301, headers({ ...good, location: 'https://example.com/' }))), /insecure/);
});

test('version in the Server header is flagged, a bare name is not', () => {
    assert.match(texts(headerIssues('https', 200, headers({ ...good, server: 'Apache/2.4.41 (Ubuntu)' }))), /reveals software versions/);
    assert.doesNotMatch(texts(headerIssues('https', 200, headers(good))), /reveals/);
});

test('unsafe CSP sources are found', () => {
    assert.deepEqual(unsafeCsp("default-src 'self'"), []);
    assert.deepEqual(unsafeCsp("script-src 'self' 'unsafe-inline' 'unsafe-eval'"), ["'unsafe-inline'", "'unsafe-eval'"]);
    assert.deepEqual(unsafeCsp("script-src 'self' 'unsafe-inline' 'nonce-abc'"), []);
    assert.deepEqual(unsafeCsp('default-src *'), ['a wildcard script source']);
    assert.deepEqual(unsafeCsp('frame-ancestors none'), []);
});

test('X-Frame-Options must be DENY or SAMEORIGIN', () => {
    const base = { 'strict-transport-security': 'x', 'content-security-policy': "default-src 'self'" };
    assert.match(texts(headerIssues('https', 200, headers({ ...base, 'x-frame-options': 'ALLOW-FROM https://a.com' }))), /browsers ignore/);
    assert.doesNotMatch(texts(headerIssues('https', 200, headers({ ...base, 'x-frame-options': 'sameorigin' }))), /X-Frame|clickjacking/);
});

test('cookie flags are checked', () => {
    const issues = cookieIssues(['a=1; Path=/', 'b=2; HttpOnly; Secure', 'c=3; secure'], 'https');
    assert.match(texts(issues), /without HttpOnly \(a, c\)/);
    assert.match(texts(issues), /without Secure \(a\)/);
    assert.equal(cookieIssues(['a=1'], 'http').length, 1);
});

test('certificate lifetime rules', () => {
    const now = Date.parse('2026-06-01T00:00:00Z');
    assert.equal(certificateLifetimeIssues('Jan 1 00:00:00 2025 GMT', 'Jan 1 00:00:00 2026 GMT', now)[0].severity, 'HIGH');
    assert.equal(certificateLifetimeIssues('Jan 1 00:00:00 2026 GMT', 'Jun 20 00:00:00 2026 GMT', now)[0].severity, 'MEDIUM');
    // A one year certificate with 45 days left has used more than 80%.
    const low = certificateLifetimeIssues('Jul 16 00:00:00 2025 GMT', 'Jul 16 00:00:00 2026 GMT', now);
    assert.equal(low[0].severity, 'LOW');
    assert.deepEqual(certificateLifetimeIssues('Jan 1 00:00:00 2026 GMT', 'Jan 1 00:00:00 2027 GMT', now), []);
});

test('DS records in a DoH answer', () => {
    assert.equal(dsPublished({ Status: 0, Answer: [{ type: 43 }] }), true);
    assert.equal(dsPublished({ Status: 0 }), false);
    assert.equal(dsPublished({ Status: 2 }), null);
    assert.equal(dsPublished(null), null);
});
