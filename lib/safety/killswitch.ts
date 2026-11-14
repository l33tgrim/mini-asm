import fs from 'fs';
import path from 'path';

/**
 * Global kill switch. If the env var MINIASM_KILL is set, or a STOP file exists
 * at the project root, every active action is refused immediately. This lets an
 * operator halt an in-flight engagement without killing the process.
 */
const STOP_FILE = path.join(process.cwd(), '.miniasm-stop');

export function isKillActive(): boolean {
    if (process.env.MINIASM_KILL && process.env.MINIASM_KILL !== '0' && process.env.MINIASM_KILL !== 'false') {
        return true;
    }
    try {
        return fs.existsSync(STOP_FILE);
    } catch {
        return false;
    }
}

export function assertNotKilled(): void {
    if (isKillActive()) {
        throw new Error('KILL_SWITCH_ACTIVE: engagement halted by operator (MINIASM_KILL / .miniasm-stop)');
    }
}
