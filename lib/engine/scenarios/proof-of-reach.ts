import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices } from './_shared';
import { tcpConnect } from '../primitives';

// Services whose mere reachability is a meaningful proof for a report.
const REACH_TARGETS: Record<number, { name: string; severity: Severity }> = {
    6379: { name: 'Redis', severity: 'HIGH' },
    9200: { name: 'Elasticsearch', severity: 'HIGH' },
    2375: { name: 'Docker API', severity: 'CRITICAL' },
    11211: { name: 'Memcached', severity: 'HIGH' },
    27017: { name: 'MongoDB', severity: 'HIGH' },
    3306: { name: 'MySQL', severity: 'HIGH' },
    5432: { name: 'PostgreSQL', severity: 'HIGH' },
    5900: { name: 'VNC', severity: 'HIGH' },
    3389: { name: 'RDP', severity: 'MEDIUM' },
    10250: { name: 'Kubelet', severity: 'HIGH' },
};

/**
 * Non-destructive proof of reach: confirm a live TCP connection to sensitive
 * services. This proves network reachability only; nothing is sent beyond the
 * handshake.
 */
export const proofOfReach: Scenario = {
    id: 'proof-of-reach',
    name: 'Proof of Reach',
    description: 'Prove a live connection can be established to sensitive services. Connection only, no payload.',
    category: 'PROOF',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Discovery',
    attckTechnique: 'T1046 Network Service Discovery',
    requiresActive: true,
    intrusive: true,
    tags: ['proof', 'reach'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        const sensitive = services.filter((s) => REACH_TARGETS[s.port]);

        if (sensitive.length === 0) {
            results.push({ title: 'No sensitive services to reach', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No sensitive service ports found in scope.' });
            return results;
        }

        for (const s of sensitive) {
            const meta = REACH_TARGETS[s.port];
            const reachable = await tcpConnect(s.ip, s.port, 2000);
            if (reachable) {
                results.push({
                    title: `Proven reach to ${meta.name} at ${s.ip}:${s.port}`,
                    severity: meta.severity,
                    outcome: 'PROVEN',
                    target: `${s.ip}:${s.port}`,
                    attckTactic: 'Discovery',
                    attckTechnique: 'T1046 Network Service Discovery',
                    evidence: `TCP handshake to ${s.ip}:${s.port} (${meta.name}) completed at ${new Date().toISOString()}. Reachability confirmed; no data sent.`,
                    remediation: `Restrict ${meta.name} to a private network / VPN and firewall the port from the internet.`,
                });
            }
        }
        return results;
    },
};
