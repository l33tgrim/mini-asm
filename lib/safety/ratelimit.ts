/**
 * Simple per-host token bucket so we never hammer a target. Shared across a
 * process. Defaults are deliberately polite.
 */
interface Bucket {
    tokens: number;
    last: number;
}

const buckets = new Map<string, Bucket>();

const DEFAULT_RATE = Number(process.env.MINIASM_RATE_PER_SEC || 8); // requests/sec/host
const DEFAULT_BURST = Number(process.env.MINIASM_BURST || 16);

export async function acquire(host: string, rate = DEFAULT_RATE, burst = DEFAULT_BURST): Promise<void> {
    const now = Date.now();
    let b = buckets.get(host);
    if (!b) {
        b = { tokens: burst, last: now };
        buckets.set(host, b);
    }
    // Refill.
    const elapsed = (now - b.last) / 1000;
    b.tokens = Math.min(burst, b.tokens + elapsed * rate);
    b.last = now;

    if (b.tokens >= 1) {
        b.tokens -= 1;
        return;
    }
    // Wait for one token.
    const waitMs = Math.ceil(((1 - b.tokens) / rate) * 1000);
    await new Promise((r) => setTimeout(r, waitMs));
    b.tokens = 0;
    b.last = Date.now();
}

export function resetRateLimiter(): void {
    buckets.clear();
}
