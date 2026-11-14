import { NextResponse, type NextRequest } from 'next/server';
import { authDisabled, configuredCredentials, credentialsMatch, SESSION_COOKIE, verifySession } from '@/lib/auth/session';

// Access control for the whole app. This tool can launch network scans, so it
// must never be reachable without credentials.
//
//   ASM_USERNAME / ASM_PASSWORD   credentials for the sign-in page (and Basic auth for scripts)
//   ASM_SESSION_SECRET            optional key for signing sessions
//   ASM_AUTH_DISABLED=true        explicit opt-out, for a trusted local machine only

const PUBLIC_PATHS = new Set(['/login', '/api/auth/login', '/api/auth/session']);

function basicAuthOk(request: NextRequest, creds: { username: string; password: string }): boolean {
    const header = request.headers.get('authorization') || '';
    if (!header.startsWith('Basic ')) return false;
    let decoded: string;
    try {
        decoded = atob(header.slice(6));
    } catch {
        return false;
    }
    const split = decoded.indexOf(':');
    if (split < 0) return false;
    return credentialsMatch(creds, decoded.slice(0, split), decoded.slice(split + 1));
}

function isCrossSiteWrite(request: NextRequest): boolean {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return false;
    if (request.headers.get('sec-fetch-site') === 'cross-site') return true;
    const origin = request.headers.get('origin');
    if (!origin) return false;
    try {
        return new URL(origin).host !== request.headers.get('host');
    } catch {
        return true;
    }
}

export async function proxy(request: NextRequest) {
    // Session cookies are sent automatically, so state-changing requests from
    // other sites have to be refused explicitly.
    if (isCrossSiteWrite(request)) {
        return NextResponse.json({ error: 'Cross-site requests are not allowed.' }, { status: 403 });
    }

    const { pathname, search } = request.nextUrl;
    const creds = configuredCredentials();

    if (!creds) {
        if (authDisabled()) {
            return pathname === '/login' ? NextResponse.redirect(new URL('/', request.url)) : NextResponse.next();
        }
        return new NextResponse(
            'Mini ASM is not configured. Set ASM_USERNAME and ASM_PASSWORD (or ASM_AUTH_DISABLED=true on a trusted local machine) and restart.',
            { status: 503 },
        );
    }

    const user = await verifySession(request.cookies.get(SESSION_COOKIE)?.value, creds);
    if (pathname === '/login' && user) return NextResponse.redirect(new URL('/', request.url));
    if (user || PUBLIC_PATHS.has(pathname)) return NextResponse.next();

    // Scripts and the CLI can still send Basic credentials with each request.
    if (basicAuthOk(request, creds)) return NextResponse.next();

    if (pathname.startsWith('/api/')) {
        return NextResponse.json({ error: 'Sign in required.' }, { status: 401 });
    }
    const login = new URL('/login', request.url);
    if (pathname !== '/') login.searchParams.set('next', pathname + search);
    return NextResponse.redirect(login);
}

export const config = {
    matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
