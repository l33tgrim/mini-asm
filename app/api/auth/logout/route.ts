import { NextResponse } from 'next/server';
import { SESSION_COOKIE } from '@/lib/auth/session';

/**
 * Clears the session and sends the browser back to the sign-in page. The
 * redirect is relative because inside the container the request URL carries
 * the bind address (0.0.0.0), not the host the browser used.
 */
export async function POST() {
    const res = new NextResponse(null, { status: 303, headers: { Location: '/login' } });
    res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, sameSite: 'strict', path: '/', maxAge: 0 });
    return res;
}
