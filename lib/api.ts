import { NextResponse } from 'next/server';
import { TargetError } from './targets';
import { ScanError } from './scan-runner';

/** Reads a JSON object body, returning null when the body is missing or malformed. */
export async function readJsonBody(req: Request): Promise<Record<string, unknown> | null> {
    try {
        const body = await req.json();
        return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
    } catch {
        return null;
    }
}

export function errorResponse(message: string, status: number) {
    return NextResponse.json({ error: message }, { status });
}

/** Maps known error types to a response. Anything unexpected is logged and reported generically. */
export function handleError(context: string, error: unknown) {
    if (error instanceof TargetError) return errorResponse(error.message, 400);
    if (error instanceof ScanError) return errorResponse(error.message, error.status);
    console.error(`${context}:`, error);
    return errorResponse('Something went wrong on the server.', 500);
}
