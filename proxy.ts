import { NextResponse, type NextRequest } from 'next/server';

// Access control for the whole app. This tool can launch network scans, so it
// must never be reachable without credentials.
//
//   ASM_USERNAME / ASM_PASSWORD   credentials for HTTP Basic authentication
//   ASM_AUTH_DISABLED=true        explicit opt-out, for a trusted local machine only

function safeEqual(a: string, b: string): boolean {
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return diff === 0;
}

function isAuthorised(request: NextRequest, username: string, password: string): boolean {
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
    const userOk = safeEqual(decoded.slice(0, split), username);
    const passOk = safeEqual(decoded.slice(split + 1), password);
    return userOk && passOk;
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

export function proxy(request: NextRequest) {
    // Browsers attach Basic credentials automatically, so state-changing requests
    // from other sites have to be refused explicitly.
    if (isCrossSiteWrite(request)) {
        return NextResponse.json({ error: 'Cross-site requests are not allowed.' }, { status: 403 });
    }

    const username = process.env.ASM_USERNAME;
    const password = process.env.ASM_PASSWORD;

    if (!username || !password) {
        const optedOut = process.env.ASM_AUTH_DISABLED === 'true';
        if (optedOut || process.env.NODE_ENV !== 'production') return NextResponse.next();
        return new NextResponse(
            'Mini ASM is not configured. Set ASM_USERNAME and ASM_PASSWORD (or ASM_AUTH_DISABLED=true on a trusted local machine) and restart.',
            { status: 503 },
        );
    }

    if (isAuthorised(request, username, password)) return NextResponse.next();

    return new NextResponse('Authentication required.', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Basic realm="Mini ASM", charset="UTF-8"' },
    });
}

export const config = {
    matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
