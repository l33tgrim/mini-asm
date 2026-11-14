import test from 'node:test';
import assert from 'node:assert/strict';
import { createSession, verifySession, safeNextPath, credentialsMatch } from '../lib/auth/session';

const creds = { username: 'admin', password: 'correct horse' };

test('a session round-trips and names the user', async () => {
    const token = await createSession(creds);
    assert.equal(await verifySession(token, creds), 'admin');
});

test('tampered, expired and re-keyed sessions are rejected', async () => {
    const token = await createSession(creds);
    const [u, exp, sig] = token.split('.');
    assert.equal(await verifySession(`${u}.${Number(exp) + 1000}.${sig}`, creds), null);
    assert.equal(await verifySession(token, creds, Number(exp) + 1), null);
    assert.equal(await verifySession(token, { ...creds, password: 'changed' }), null);
    assert.equal(await verifySession('garbage', creds), null);
    assert.equal(await verifySession(undefined, creds), null);
});

test('credentials must match exactly', () => {
    assert.ok(credentialsMatch(creds, 'admin', 'correct horse'));
    assert.ok(!credentialsMatch(creds, 'admin', 'correct hors'));
    assert.ok(!credentialsMatch(creds, 'Admin', 'correct horse'));
});

test('redirect after sign-in stays inside the app', () => {
    assert.equal(safeNextPath('/scans/abc?x=1'), '/scans/abc?x=1');
    assert.equal(safeNextPath('//evil.example'), '/');
    assert.equal(safeNextPath('/\\evil.example'), '/');
    assert.equal(safeNextPath('https://evil.example'), '/');
    assert.equal(safeNextPath('/login'), '/');
    assert.equal(safeNextPath(null), '/');
});
