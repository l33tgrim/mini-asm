import { NextResponse, type NextRequest } from 'next/server';
import { configuredCredentials, createSession, credentialsMatch, SESSION_COOKIE, SESSION_HOURS } from '@/lib/auth/session';

// Slow down password guessing: 10 failed attempts per address per 15 minutes.
const WINDOW_MS = 15 * 60_000;
const MAX_FAILURES = 10;
const failures = new Map<string, { count: number; first: number }>();

function clientKey(request: NextRequest): string {
    return request.headers.get('x-forwarded-for')?.split(',')[0].trim() || request.headers.get('x-real-ip') || 'local';
}

export async function POST(request: NextRequest) {
    const creds = configuredCredentials();
    if (!creds) return NextResponse.json({ error: 'Sign-in is not configured on this server.' }, { status: 503 });

    const who = clientKey(request);
    const now = Date.now();
    const record = failures.get(who);
    if (record && now - record.first > WINDOW_MS) failures.delete(who);
    const current = failures.get(who);
    if (current && current.count >= MAX_FAILURES) {
        const minutes = Math.ceil((WINDOW_MS - (now - current.first)) / 60_000);
        return NextResponse.json({ error: `Too many failed attempts. Try again in ${minutes} minute(s).` }, { status: 429 });
    }

    let body: { username?: unknown; password?: unknown };
    try {
        body = await request.json();
    } catch {
        return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
    }
    const username = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!credentialsMatch(creds, username, password)) {
        const entry = failures.get(who) || { count: 0, first: now };
        entry.count++;
        failures.set(who, entry);
        await new Promise((r) => setTimeout(r, 400));
        return NextResponse.json({ error: 'Incorrect username or password.' }, { status: 401 });
    }

    failures.delete(who);
    const res = NextResponse.json({ ok: true });
    res.cookies.set(SESSION_COOKIE, await createSession(creds), {
        httpOnly: true,
        sameSite: 'strict',
        secure: request.nextUrl.protocol === 'https:',
        path: '/',
        maxAge: SESSION_HOURS * 3600,
    });
    return res;
}
