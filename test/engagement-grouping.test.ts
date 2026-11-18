import test from 'node:test';
import assert from 'node:assert/strict';
import { groupResults, issueTitle } from '../lib/group-results';
import { dmarcPolicy, spfAll } from '../lib/engine/scenarios/email-posture';

test('host parts are removed from titles', () => {
    assert.equal(issueTitle('Weak cookie attributes on www.a.co.za:443'), 'Weak cookie attributes');
    assert.equal(issueTitle('Software versions disclosed by 10.0.0.1:80'), 'Software versions disclosed');
    assert.equal(issueTitle('CVE-2021-41773 on 1.2.3.4:80 (Apache)'), 'CVE-2021-41773 (Apache)');
    assert.equal(issueTitle('No SPF record'), 'No SPF record');
});

test('results are grouped per issue and reruns replace older runs', () => {
    const r = (id: string, title: string, outcome = 'VULNERABLE', evidence = 'e') => ({ id, title, severity: 'LOW', outcome, evidence });
    const groups = groupResults([
        { id: '1', scenarioName: 'Cookies', target: 'a.com', createdAt: '2026-01-01', results: [r('1', 'Weak cookie attributes on a.com:443', 'VULNERABLE', 'old')] },
        { id: '2', scenarioName: 'Cookies', target: 'a.com', createdAt: '2026-02-01', results: [r('2', 'Weak cookie attributes on a.com:443')] },
        { id: '3', scenarioName: 'Cookies', target: 'b.com', createdAt: '2026-02-01', results: [r('3', 'Weak cookie attributes on b.com:443')] },
        { id: '4', scenarioName: 'Headers', target: 'b.com', createdAt: '2026-02-01', results: [r('4', 'Strong headers on b.com:443', 'SECURE')] },
    ]);
    assert.equal(groups.length, 2);
    assert.equal(groups[0].title, 'Weak cookie attributes');
    assert.equal(groups[0].items.length, 2);
    assert.ok(groups[0].items.every((i) => i.result.evidence === 'e'));
    assert.equal(groups[1].outcome, 'SECURE');
});

test('DMARC policy ignores sp= and reads it for subdomains', () => {
    assert.equal(dmarcPolicy('v=DMARC1; sp=none; p=reject'), 'reject');
    assert.equal(dmarcPolicy('v=DMARC1; p=reject; sp=none', true), 'none');
    assert.equal(dmarcPolicy('v=DMARC1; p=quarantine', true), 'quarantine');
    assert.equal(dmarcPolicy('v=DMARC1; rua=mailto:a@b.c'), 'none');
});

test('SPF all mechanism', () => {
    assert.equal(spfAll('v=spf1 include:spf.protection.outlook.com -all'), '-');
    assert.equal(spfAll('v=spf1 a mx ~all'), '~');
    assert.equal(spfAll('v=spf1 +all'), '+');
    assert.equal(spfAll('v=spf1 all'), '+');
    assert.equal(spfAll('v=spf1 include:_spf.allstate.com'), null);
});
