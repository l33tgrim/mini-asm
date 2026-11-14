import { NextResponse, type NextRequest } from 'next/server';
import { authDisabled, configuredCredentials, SESSION_COOKIE, verifySession } from '@/lib/auth/session';

export const dynamic = 'force-dynamic';

/** Tells the UI whether sign-in is in use and who is signed in. */
export async function GET(request: NextRequest) {
    const creds = configuredCredentials();
    const user = creds ? await verifySession(request.cookies.get(SESSION_COOKIE)?.value, creds) : null;
    return NextResponse.json({ authEnabled: !!creds && !authDisabled(), user });
}
