import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateGate, type EngagementContext } from '@/lib/engine/runner';
import { getScenario } from '@/lib/engine/registry';
import { isTargetInScope, assertActiveAllowed, classifyScope } from '@/lib/safety/scope';
import { checkAllowedCommand } from '@/lib/safety/commandAllowlist';

const safeScenario = getScenario('recon-exposure')!; // requiresActive: false
const activeScenario = getScenario('proof-of-reach')!; // requiresActive: true

function ctx(over: Partial<EngagementContext> = {}): EngagementContext {
    return {
        engagementId: 'test',
        mode: 'ACTIVE',
        actor: 'test',
        authorized: true,
        scope: [{ value: 'example.com', kind: 'DOMAIN', verified: true }],
        ...over,
    };
}

test('scope: subdomain matches a domain scope entry', () => {
    const r = isTargetInScope('api.example.com', [{ value: 'example.com', kind: 'DOMAIN', verified: true }]);
    assert.equal(r.inScope, true);
});

test('scope: unrelated domain is rejected', () => {
    const r = isTargetInScope('evil.com', [{ value: 'example.com', kind: 'DOMAIN', verified: true }]);
    assert.equal(r.inScope, false);
});

test('scope: IP inside CIDR matches', () => {
    const r = isTargetInScope('10.0.0.42', [{ value: '10.0.0.0/24', kind: 'CIDR', verified: true }]);
    assert.equal(r.inScope, true);
});

test('scope: IP outside CIDR is rejected', () => {
    const r = isTargetInScope('10.0.1.42', [{ value: '10.0.0.0/24', kind: 'CIDR', verified: true }]);
    assert.equal(r.inScope, false);
});

test('classifyScope detects kinds', () => {
    assert.equal(classifyScope('example.com'), 'DOMAIN');
    assert.equal(classifyScope('10.0.0.1'), 'IP');
    assert.equal(classifyScope('10.0.0.0/24'), 'CIDR');
});

test('GATE: out-of-scope target is blocked for any scenario', () => {
    const g = evaluateGate(safeScenario, 'notmine.com', ctx());
    assert.equal(g.allowed, false);
    assert.match(g.reason, /OUT_OF_SCOPE/);
});

test('GATE: safe scenario runs on an in-scope, unauthorized engagement', () => {
    const g = evaluateGate(safeScenario, 'example.com', ctx({ authorized: false, mode: 'SAFE' }));
    assert.equal(g.allowed, true);
});

test('GATE: active scenario is blocked when engagement is not authorized', () => {
    const g = evaluateGate(activeScenario, 'example.com', ctx({ authorized: false }));
    assert.equal(g.allowed, false);
    assert.match(g.reason, /NOT_AUTHORIZED/);
});

test('GATE: active scenario is blocked in SAFE mode even if authorized', () => {
    const g = evaluateGate(activeScenario, 'example.com', ctx({ mode: 'SAFE' }));
    assert.equal(g.allowed, false);
});

test('GATE: active scenario is blocked when scope is not ownership-verified', () => {
    const g = evaluateGate(activeScenario, 'example.com', ctx({ scope: [{ value: 'example.com', kind: 'DOMAIN', verified: false }] }));
    assert.equal(g.allowed, false);
    assert.match(g.reason, /NOT_VERIFIED/);
});

test('GATE: active scenario is allowed only when authorized + ACTIVE + verified + in scope', () => {
    const g = evaluateGate(activeScenario, 'api.example.com', ctx());
    assert.equal(g.allowed, true);
});

test('assertActiveAllowed requires a verified matched entry', () => {
    const unverified = assertActiveAllowed('example.com', [{ value: 'example.com', kind: 'DOMAIN', verified: false }]);
    assert.equal(unverified.allowed, false);
    const verified = assertActiveAllowed('example.com', [{ value: 'example.com', kind: 'DOMAIN', verified: true }]);
    assert.equal(verified.allowed, true);
});

test('command allowlist: benign commands pass', () => {
    assert.equal(checkAllowedCommand('id').allowed, true);
    assert.equal(checkAllowedCommand('whoami').allowed, true);
});

test('command allowlist: anything off-list is refused', () => {
    assert.equal(checkAllowedCommand('rm').allowed, false);
    assert.equal(checkAllowedCommand('curl').allowed, false);
    assert.equal(checkAllowedCommand('cat /etc/passwd').allowed, false);
});
