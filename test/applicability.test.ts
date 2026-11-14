import { test } from 'node:test';
import assert from 'node:assert/strict';
import { suggestScenarios } from '../lib/engine/applicability';
import { listScenarios } from '../lib/engine/registry';

const ids = (target: string, ports: number[]) => suggestScenarios({ target, ports: ports.map((port) => ({ port })) }).map((s) => s.scenarioId);

test('every suggested scenario exists in the registry', () => {
    const known = new Set(listScenarios().map((s) => s.id));
    for (const id of ids('a.example.com', [22, 80, 443, 6379, 9200, 27017])) assert.ok(known.has(id), id);
});

test('a web host gets web and TLS checks, not mail or data proofs', () => {
    const got = ids('3.160.170.22', [53, 80, 443]);
    for (const id of ['security-headers', 'web-exposure-scan', 'web-tech-vulns', 'tls-posture', 'waf-detect-bypass']) assert.ok(got.includes(id), id);
    for (const id of ['email-posture', 'subdomain-takeover', 'proof-of-data', 'proof-of-command']) assert.ok(!got.includes(id), id);
});

test('a hostname also gets DNS and email checks', () => {
    const got = ids('businessreports.payinc.co.za', [443]);
    assert.ok(got.includes('subdomain-takeover'));
    assert.ok(got.includes('email-posture'));
});

test('exposed data stores get the matching breach proofs', () => {
    const got = ids('10.1.2.3', [6379]);
    for (const id of ['proof-of-reach', 'proof-of-command', 'proof-of-data']) assert.ok(got.includes(id), id);
    assert.ok(!got.includes('security-headers'));
});

test('a service labelled http on an odd port counts as web', () => {
    const got = suggestScenarios({ target: '10.1.2.3', ports: [{ port: 7001, service: 'HTTP' }] }).map((s) => s.scenarioId);
    assert.ok(got.includes('security-headers'));
});
