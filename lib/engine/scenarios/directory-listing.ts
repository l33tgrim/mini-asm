import type { Scenario, ScenarioResult } from '../types';
import { ensureServices, webTargetsFrom, paramList } from './_shared';
import { httpGet } from '../primitives';

const DEFAULT_DIRS = ['/', '/uploads/', '/files/', '/images/', '/assets/', '/backup/', '/static/', '/data/', '/tmp/'];

/**
 * Directory listing / autoindex exposure. Parameterized via `dirs`.
 */
export const directoryListing: Scenario = {
    id: 'directory-listing',
    name: 'Directory Listing',
    description: 'Check common paths for enabled directory listing (autoindex).',
    category: 'EXPOSURE',
    maxSeverity: 'MEDIUM',
    attckTactic: 'Discovery',
    attckTechnique: 'T1083 File and Directory Discovery',
    requiresActive: false,
    intrusive: true,
    tags: ['web', 'exposure'],
    params: [{ key: 'dirs', label: 'Directories', type: 'stringlist', help: 'Paths to test (default: /, /uploads/, ...)' }],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const dirs = paramList(ctx, 'dirs', DEFAULT_DIRS);
        const webs = webTargetsFrom(await ensureServices(ctx));
        for (const w of webs) {
            for (const d of dirs) {
                const probe = await httpGet(w.url + d, { timeout: 5000, maxBody: 2048 });
                if (probe.ok && /<title>Index of \/|Directory listing for|\[To Parent Directory\]/i.test(probe.bodySnippet)) {
                    results.push({
                        title: `Directory listing enabled at ${d} on ${w.host}:${w.port}`,
                        severity: 'MEDIUM',
                        outcome: 'VULNERABLE',
                        target: w.url + d,
                        attckTactic: 'Discovery',
                        attckTechnique: 'T1083 File and Directory Discovery',
                        evidence: `HTTP ${probe.status} returned an autoindex page at ${d} (file names redacted).`,
                        remediation: 'Disable directory autoindex (e.g. Options -Indexes / autoindex off).',
                    });
                }
            }
        }
        if (results.length === 0) results.push({ title: 'No directory listing found', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No autoindex pages on the tested paths.' });
        return results;
    },
};
