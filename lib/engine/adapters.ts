import { checkAllowedCommand } from '@/lib/safety/commandAllowlist';

/**
 * Proof-of-command adapters.
 *
 * A generic remote-code-execution engine is intentionally NOT shipped. Instead,
 * for a KNOWN weak point in your OWN application (that you have validated and
 * authorized), you register an adapter here. The adapter receives a command KEY
 * from the allowlist (never a raw string) and is responsible for driving your
 * specific exploit path to execute exactly that benign, read-only command and
 * return its output as proof.
 *
 * If no adapter matches a target, proof-of-command runs in dry-run: it reports
 * the capability and the benign command it WOULD run, and changes nothing.
 */
export interface ExecAdapter {
    id: string;
    /** Return true if this adapter applies to the given target. */
    matches: (target: string) => boolean;
    /**
     * Execute one allowlisted command key against the target and return stdout.
     * Must only ever run the resolved benign argv. Must never write/change state.
     */
    exec: (target: string, argv: string[]) => Promise<string>;
}

const adapters: ExecAdapter[] = [
    // Operators register their own, e.g.:
    // {
    //   id: 'my-app-ssti',
    //   matches: (t) => t.endsWith('staging.example.com'),
    //   exec: async (t, argv) => runThroughMyKnownSSTI(t, argv),
    // },
];

export function registerExecAdapter(a: ExecAdapter): void {
    adapters.push(a);
}

export function findExecAdapter(target: string): ExecAdapter | undefined {
    return adapters.find((a) => {
        try {
            return a.matches(target);
        } catch {
            return false;
        }
    });
}

/**
 * Run an allowlisted command key via a matching adapter, enforcing the
 * allowlist at the boundary. Returns null if no adapter matched (dry-run).
 */
export async function runProofCommand(target: string, commandKey: string): Promise<{ ran: boolean; output?: string; reason: string }> {
    const check = checkAllowedCommand(commandKey);
    if (!check.allowed || !check.argv) {
        return { ran: false, reason: check.reason };
    }
    const adapter = findExecAdapter(target);
    if (!adapter) {
        return { ran: false, reason: `no exec adapter registered for ${target}; dry-run only` };
    }
    const output = await adapter.exec(target, check.argv);
    return { ran: true, output, reason: `executed "${check.argv.join(' ')}" via adapter ${adapter.id}` };
}
