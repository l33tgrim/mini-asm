import { test } from 'node:test';
import assert from 'node:assert/strict';
import { paramString, paramList, paramJson } from '@/lib/engine/scenarios/_shared';
import type { RunContext } from '@/lib/engine/types';

function ctx(params: Record<string, unknown>): RunContext {
    return { target: 'example.com', mode: 'SAFE', state: {}, params, log: () => {} };
}

test('paramString returns value or default', () => {
    assert.equal(paramString(ctx({ a: 'hi' }), 'a'), 'hi');
    assert.equal(paramString(ctx({}), 'a', 'def'), 'def');
    assert.equal(paramString(ctx({ a: 5 }), 'a', 'def'), 'def'); // wrong type -> default
});

test('paramList accepts arrays and comma strings', () => {
    assert.deepEqual(paramList(ctx({ a: ['x', 'y'] }), 'a'), ['x', 'y']);
    assert.deepEqual(paramList(ctx({ a: 'x, y ,z' }), 'a'), ['x', 'y', 'z']);
    assert.deepEqual(paramList(ctx({}), 'a', ['d']), ['d']);
});

test('paramJson parses object, string JSON, or default', () => {
    assert.deepEqual(paramJson(ctx({ a: { n: 1 } }), 'a', {}), { n: 1 });
    assert.deepEqual(paramJson(ctx({ a: '{"n":2}' }), 'a', {}), { n: 2 });
    assert.deepEqual(paramJson(ctx({ a: 'not json' }), 'a', { fallback: true }), { fallback: true });
    assert.deepEqual(paramJson(ctx({}), 'a', [1, 2]), [1, 2]);
});

test('custom-http-checks declares a checks param', async () => {
    const { getScenario } = await import('@/lib/engine/registry');
    const s = getScenario('custom-http-checks');
    assert.ok(s, 'scenario registered');
    assert.equal(s!.params?.[0]?.key, 'checks');
    assert.equal(s!.requiresActive, false);
});
