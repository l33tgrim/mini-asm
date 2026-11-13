/**
 * Command allowlist for proof-of-command scenarios.
 *
 * When a scenario proves code execution on an in-scope, verified target, it is
 * allowed to run EXACTLY ONE benign, read-only command from this list to
 * capture evidence. Nothing here writes, deletes, pivots, or changes state.
 * Anything not on this list is refused by the engine, even if a scenario asks.
 */
export const ALLOWED_COMMANDS: Record<string, { argv: string[]; purpose: string }> = {
    id: { argv: ['id'], purpose: 'prove execution context (uid/gid)' },
    whoami: { argv: ['whoami'], purpose: 'prove the running user' },
    hostname: { argv: ['hostname'], purpose: 'prove which host was reached' },
    'uname-a': { argv: ['uname', '-a'], purpose: 'prove the OS/kernel reached' },
    pwd: { argv: ['pwd'], purpose: 'prove the working directory' },
};

const DESTRUCTIVE_TOKENS = [
    'rm', 'mv', 'cp', 'dd', 'mkfs', 'kill', 'shutdown', 'reboot', 'curl', 'wget',
    'nc', 'ncat', 'bash', 'sh', 'python', 'perl', 'chmod', 'chown', 'tee',
    'iptables', 'systemctl', 'service', 'useradd', 'passwd', 'echo', 'cat',
    '>', '>>', '|', ';', '&', '$(', '`',
];

export interface CommandCheck {
    allowed: boolean;
    reason: string;
    argv?: string[];
}

/**
 * Validate a requested proof-of-command key against the allowlist. Scenarios
 * reference a command by KEY (e.g. "id"), never by a raw string, so there is no
 * path for arbitrary command construction.
 */
export function checkAllowedCommand(key: string): CommandCheck {
    const entry = ALLOWED_COMMANDS[key];
    if (!entry) {
        return { allowed: false, reason: `command "${key}" is not on the allowlist` };
    }
    // Defence in depth: reject if any argv element smells destructive.
    const joined = entry.argv.join(' ').toLowerCase();
    for (const tok of DESTRUCTIVE_TOKENS) {
        if (entry.argv.some((a) => a.toLowerCase() === tok)) {
            return { allowed: false, reason: `command "${key}" contains forbidden token "${tok}"` };
        }
        if (joined.includes(tok) && (tok.length > 1)) {
            // only block shell metacharacters here, word tokens handled above
            if (['>', '>>', '|', ';', '&', '$(', '`'].includes(tok)) {
                return { allowed: false, reason: `command "${key}" contains shell metacharacter "${tok}"` };
            }
        }
    }
    return { allowed: true, reason: entry.purpose, argv: entry.argv };
}

export function listAllowedCommands(): { key: string; command: string; purpose: string }[] {
    return Object.entries(ALLOWED_COMMANDS).map(([key, v]) => ({
        key,
        command: v.argv.join(' '),
        purpose: v.purpose,
    }));
}
