import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreResults } from '@/lib/report/risk';
import { deterministicPlan } from '@/lib/engine/autopilot';
import type { EngagementContext } from '@/lib/engine/runner';
import type { ScenarioResult } from '@/lib/engine/types';
import type { ServiceRef } from '@/lib/engine/scenarios/_shared';

const r = (severity: ScenarioResult['severity'], outcome: ScenarioResult['outcome']): ScenarioResult => ({ title: 't', severity, outcome });

test('clean results score 100 / grade A', () => {
    const s = scoreResults([r('INFO', 'SECURE'), r('HIGH', 'SECURE')]);
    assert.equal(s.score, 100);
    assert.equal(s.grade, 'A');
});

test('a proven critical tanks the score below an unproven one', () => {
    const proven = scoreResults([r('CRITICAL', 'PROVEN')]).score;
    const unproven = scoreResults([r('CRITICAL', 'VULNERABLE')]).score;
    assert.ok(proven < unproven, 'proven should score worse');
    assert.ok(proven < 55);
});

test('score decreases as weaknesses accumulate', () => {
    const few = scoreResults([r('LOW', 'VULNERABLE')]).score;
    const many = scoreResults([r('HIGH', 'VULNERABLE'), r('HIGH', 'VULNERABLE'), r('CRITICAL', 'VULNERABLE')]).score;
    assert.ok(many < few);
});

function eng(over: Partial<EngagementContext> = {}): EngagementContext {
    return { mode: 'SAFE', scope: [], actor: 't', authorized: false, ...over };
}
const web: ServiceRef[] = [{ ip: '1.1.1.1', port: 443, service: 'HTTPS' }];
const redis: ServiceRef[] = [{ ip: '1.1.1.1', port: 6379, service: 'Redis' }];

test('planner adds web scenarios when a web service is present', () => {
    const plan = deterministicPlan(web, 'example.com', eng()).map((p) => p.scenarioId);
    assert.ok(plan.includes('security-headers'));
    assert.ok(plan.includes('cors-misconfig'));
});

test('planner does NOT plan active proofs in SAFE mode', () => {
    const plan = deterministicPlan(redis, '1.1.1.1', eng({ mode: 'SAFE' })).map((p) => p.scenarioId);
    assert.ok(!plan.includes('proof-of-reach'));
    assert.ok(!plan.includes('proof-of-data'));
});

test('planner adds active proofs only when authorized + ACTIVE + sensitive surface', () => {
    const plan = deterministicPlan(redis, '1.1.1.1', eng({ mode: 'ACTIVE', authorized: true })).map((p) => p.scenarioId);
    assert.ok(plan.includes('proof-of-reach'));
    assert.ok(plan.includes('proof-of-data'));
});

test('planner adds domain-only scenarios for a domain target', () => {
    const plan = deterministicPlan(web, 'example.com', eng()).map((p) => p.scenarioId);
    assert.ok(plan.includes('email-posture'));
    assert.ok(plan.includes('subdomain-takeover'));
});
