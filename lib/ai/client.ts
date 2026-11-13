/**
 * Minimal, optional Claude API client. Used by the scenario generator to draft
 * new scenario specs. If no API key is present, callers fall back to a local
 * template and the agent (or a human) fills in the logic.
 *
 * We use the most capable generally-available model by default (Fable 5.2).
 */
export const DEFAULT_MODEL = process.env.MINIASM_MODEL || 'claude-fable-5-2';

export function hasClaudeKey(): boolean {
    return !!process.env.ANTHROPIC_API_KEY;
}

export interface ClaudeResult {
    ok: boolean;
    text?: string;
    error?: string;
}

export async function askClaude(system: string, user: string, maxTokens = 2000): Promise<ClaudeResult> {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return { ok: false, error: 'ANTHROPIC_API_KEY not set' };

    try {
        const res = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                'x-api-key': key,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: DEFAULT_MODEL,
                max_tokens: maxTokens,
                system,
                messages: [{ role: 'user', content: user }],
            }),
            signal: AbortSignal.timeout(60000),
        });
        if (!res.ok) {
            return { ok: false, error: `Claude API HTTP ${res.status}: ${(await res.text()).slice(0, 300)}` };
        }
        const data = (await res.json()) as { content?: { type: string; text?: string }[] };
        const text = (data.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
        return { ok: true, text };
    } catch (e) {
        return { ok: false, error: (e as Error).message };
    }
}
