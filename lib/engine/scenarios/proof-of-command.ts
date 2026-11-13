import type { Scenario, ScenarioResult } from '../types';
import { ensureServices } from './_shared';
import { redisReadOnly, httpGet } from '../primitives';
import { runProofCommand } from '../adapters';
import { listAllowedCommands } from '@/lib/safety/commandAllowlist';

/**
 * Non-destructive proof of command execution.
 *
 * Against misconfigured, unauthenticated services we execute a single
 * read-only server command and capture its output as undeniable proof that we
 * reached it AND ran a command. For OS-level execution we use operator-supplied
 * exec adapters (see adapters.ts); with none registered we report the
 * capability in dry-run and run nothing.
 */
export const proofOfCommand: Scenario = {
    id: 'proof-of-command',
    name: 'Proof of Command Execution',
    description: 'Run one benign, read-only command against reachable services (Redis INFO, Docker /version, Elasticsearch) and capture output as proof. OS exec via operator adapters only.',
    category: 'PROOF',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Execution',
    attckTechnique: 'T1059 Command and Scripting Interpreter',
    requiresActive: true,
    intrusive: true,
    tags: ['proof', 'command', 'execution'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        let anyProof = false;

        for (const s of services) {
            // Redis: run INFO (read-only) and capture the server version line.
            if (s.port === 6379) {
                const info = await redisReadOnly(s.ip, s.port, 'INFO');
                if (info && /redis_version:/i.test(info)) {
                    anyProof = true;
                    const version = info.match(/redis_version:([^\r\n]+)/i)?.[1]?.trim();
                    results.push({
                        title: `Executed Redis INFO on ${s.ip}:${s.port}`,
                        severity: 'CRITICAL',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Execution',
                        attckTechnique: 'T1059 Command and Scripting Interpreter',
                        evidence: `Unauthenticated. Ran read-only command INFO; server responded (redis_version=${version}). No keys read or written.`,
                        remediation: 'Require Redis auth (requirepass/ACL), bind to localhost, firewall port 6379.',
                    });
                }
            }

            // Docker API: GET /version is a server command over the API.
            if (s.port === 2375) {
                const probe = await httpGet(`http://${s.ip}:${s.port}/version`, { timeout: 5000 });
                if (probe.ok && /ApiVersion|Version/i.test(probe.bodySnippet)) {
                    anyProof = true;
                    const v = probe.bodySnippet.match(/"Version"\s*:\s*"([^"]+)"/)?.[1];
                    results.push({
                        title: `Executed Docker API /version on ${s.ip}:${s.port}`,
                        severity: 'CRITICAL',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Execution',
                        attckTechnique: 'T1610 Deploy Container',
                        evidence: `Unauthenticated Docker API. GET /version returned${v ? ' Docker ' + v : ' a valid response'}. This API can control containers; we only read the version.`,
                        remediation: 'Never expose the Docker API. Require TLS + client cert auth and firewall the port.',
                    });
                }
            }

            // Elasticsearch: GET / returns cluster info (a read command).
            if (s.port === 9200) {
                const probe = await httpGet(`http://${s.ip}:${s.port}/`, { timeout: 5000 });
                if (probe.ok && /cluster_name|lucene_version/i.test(probe.bodySnippet)) {
                    anyProof = true;
                    const cn = probe.bodySnippet.match(/"cluster_name"\s*:\s*"([^"]+)"/)?.[1];
                    results.push({
                        title: `Queried Elasticsearch on ${s.ip}:${s.port}`,
                        severity: 'HIGH',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Execution',
                        evidence: `Unauthenticated Elasticsearch. GET / returned cluster info${cn ? ' (cluster_name=' + cn + ')' : ''}. Read-only call; no documents retrieved.`,
                        remediation: 'Enable Elasticsearch security, require auth, firewall port 9200.',
                    });
                }
            }
        }

        // OS-level command execution via operator adapters (your own known weak points).
        const osProof = await runProofCommand(ctx.target, 'id');
        if (osProof.ran) {
            results.push({
                title: `Proven OS command execution on ${ctx.target}`,
                severity: 'CRITICAL',
                outcome: 'PROVEN',
                target: ctx.target,
                attckTactic: 'Execution',
                attckTechnique: 'T1059 Command and Scripting Interpreter',
                evidence: `${osProof.reason}\nOutput:\n${osProof.output}`,
                remediation: 'Patch the exploited path and restrict execution context.',
            });
        } else if (!anyProof) {
            const allow = listAllowedCommands().map((c) => `${c.key}: ${c.command}`).join('; ');
            results.push({
                title: 'No command execution proven (dry-run)',
                severity: 'INFO',
                outcome: 'INFO',
                target: ctx.target,
                evidence: `No unauthenticated command surface found and ${osProof.reason}. If an exec adapter were registered, the proof would run one allowlisted command (${allow}).`,
            });
        }
        return results;
    },
};
