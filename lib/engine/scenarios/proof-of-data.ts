import type { Scenario, ScenarioResult } from '../types';
import { ensureServices } from './_shared';
import { redisReadOnly, httpGet } from '../primitives';

/**
 * Non-destructive proof of data reach.
 *
 * Against unauthenticated data stores we prove we can read, but return ONLY
 * metadata: counts, index/collection names, sizes. We never SELECT, dump, or
 * copy actual records. This is the "reach the data, do not copy it" proof.
 */
export const proofOfData: Scenario = {
    id: 'proof-of-data',
    name: 'Proof of Data Reach',
    description: 'Prove read access to unauthenticated data stores by returning metadata only (key/doc counts, index names). No records copied.',
    category: 'PROOF',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Collection',
    attckTechnique: 'T1213 Data from Information Repositories',
    requiresActive: true,
    intrusive: true,
    tags: ['proof', 'data', 'metadata'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        let any = false;

        for (const s of services) {
            // Redis: DBSIZE returns the key count only.
            if (s.port === 6379) {
                const size = await redisReadOnly(s.ip, s.port, 'DBSIZE');
                const count = size?.match(/:(\d+)/)?.[1];
                if (count !== undefined) {
                    any = true;
                    results.push({
                        title: `Read access to Redis data on ${s.ip}:${s.port}`,
                        severity: 'CRITICAL',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Collection',
                        attckTechnique: 'T1213 Data from Information Repositories',
                        evidence: `DBSIZE = ${count} keys readable without auth. Key COUNT only; no key names or values retrieved or copied.`,
                        remediation: 'Require Redis auth, bind to localhost, firewall the port.',
                    });
                }
            }

            // Elasticsearch: list index names + doc counts (metadata).
            if (s.port === 9200) {
                const probe = await httpGet(`http://${s.ip}:${s.port}/_cat/indices?format=json&bytes=b`, { timeout: 6000, maxBody: 4096 });
                if (probe.ok && probe.bodySnippet.trim().startsWith('[')) {
                    any = true;
                    let summary = probe.bodySnippet;
                    try {
                        const idx = JSON.parse(probe.bodySnippet) as { index: string; 'docs.count': string }[];
                        summary = idx.slice(0, 15).map((i) => `${i.index}: ${i['docs.count']} docs`).join('\n');
                    } catch {
                        /* keep raw snippet */
                    }
                    results.push({
                        title: `Read access to Elasticsearch indices on ${s.ip}:${s.port}`,
                        severity: 'CRITICAL',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Collection',
                        attckTechnique: 'T1213 Data from Information Repositories',
                        evidence: `Index metadata readable without auth (names + document counts only, no documents retrieved):\n${summary}`,
                        remediation: 'Enable Elasticsearch security and firewall port 9200.',
                    });
                }
            }

            // Docker: list containers (names/images = metadata).
            if (s.port === 2375) {
                const probe = await httpGet(`http://${s.ip}:${s.port}/containers/json`, { timeout: 6000, maxBody: 4096 });
                if (probe.ok && probe.bodySnippet.trim().startsWith('[')) {
                    any = true;
                    let count = '?';
                    try {
                        count = String((JSON.parse(probe.bodySnippet) as unknown[]).length);
                    } catch {
                        /* ignore */
                    }
                    results.push({
                        title: `Read access to Docker container list on ${s.ip}:${s.port}`,
                        severity: 'CRITICAL',
                        outcome: 'PROVEN',
                        target: `${s.ip}:${s.port}`,
                        attckTactic: 'Collection',
                        evidence: `Listed ${count} running container(s) via unauthenticated Docker API. Container metadata only; no filesystem or data accessed.`,
                        remediation: 'Never expose the Docker API; require TLS + auth and firewall the port.',
                    });
                }
            }

            // Binary-protocol databases: reachable, but a data proof needs an adapter.
            if ([27017, 3306, 5432].includes(s.port)) {
                results.push({
                    title: `${s.service} reachable on ${s.ip}:${s.port} (data proof needs adapter)`,
                    severity: 'HIGH',
                    outcome: 'VULNERABLE',
                    target: `${s.ip}:${s.port}`,
                    attckTactic: 'Collection',
                    evidence: `${s.service} is reachable. A metadata-only read proof for this binary protocol requires an operator-supplied adapter to stay non-destructive.`,
                    remediation: `Restrict ${s.service} to a private network and require auth.`,
                });
            }
        }

        if (!any && results.length === 0) {
            results.push({ title: 'No unauthenticated data stores reached', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No readable unauthenticated data stores found.' });
        }
        return results;
    },
};
