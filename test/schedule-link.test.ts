import test from 'node:test';
import assert from 'node:assert/strict';
import { scheduleHref } from '../lib/ui';

test('schedule link carries the target and only non-default port settings', () => {
    assert.equal(scheduleHref('example.com'), '/schedules?target=example.com');
    assert.equal(scheduleHref('example.com', null, true), '/schedules?target=example.com');
    const href = scheduleHref('203.0.113.0/24', 'default, 8000-8100', false);
    const params = new URLSearchParams(href.split('?')[1]);
    assert.equal(params.get('target'), '203.0.113.0/24');
    assert.equal(params.get('ports'), 'default, 8000-8100');
    assert.equal(params.get('udp'), '0');
});
