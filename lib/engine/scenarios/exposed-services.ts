import type { Scenario, ScenarioResult, Severity } from '../types';
import { ensureServices, webTargetsFrom } from './_shared';
import { httpGet } from '../primitives';

// Services that should essentially never face the internet unauthenticated.
const SENSITIVE_PORTS: Record<number, { name: string; severity: Severity; why: string; remediation: string }> = {
    23: { name: 'Telnet', severity: 'CRITICAL', why: 'cleartext remote management', remediation: 'Disable Telnet, use SSH.' },
    2375: { name: 'Docker API (plain)', severity: 'CRITICAL', why: 'unauthenticated container control', remediation: 'Never expose the Docker socket/API; require TLS + auth and firewall it.' },
    6379: { name: 'Redis', severity: 'HIGH', why: 'often unauthenticated key-value store', remediation: 'Bind Redis to localhost, require auth, firewall the port.' },
    9200: { name: 'Elasticsearch', severity: 'HIGH', why: 'often unauthenticated search index', remediation: 'Enable security, require auth, firewall the port.' },
    11211: { name: 'Memcached', severity: 'HIGH', why: 'unauthenticated cache, UDP amplification risk', remediation: 'Bind to localhost, disable UDP, firewall the port.' },
    27017: { name: 'MongoDB', severity: 'HIGH', why: 'often unauthenticated database', remediation: 'Enable auth, bind to private interface, firewall the port.' },
    5432: { name: 'PostgreSQL', severity: 'HIGH', why: 'database exposed to internet', remediation: 'Restrict to private network / VPN.' },
    3306: { name: 'MySQL', severity: 'HIGH', why: 'database exposed to internet', remediation: 'Restrict to private network / VPN.' },
    9000: { name: 'Portainer/Dev', severity: 'MEDIUM', why: 'management UI exposed', remediation: 'Restrict management UIs to VPN.' },
    5900: { name: 'VNC', severity: 'HIGH', why: 'remote desktop exposed', remediation: 'Tunnel VNC over VPN, require strong auth.' },
    10250: { name: 'Kubelet API', severity: 'HIGH', why: 'node control plane exposed', remediation: 'Firewall the kubelet port, require auth.' },
};

// Files that leak source, secrets, or internals if reachable.
const EXPOSED_FILES = [
    { path: '/.git/HEAD', sig: /ref:\s*refs\//i, name: 'Exposed .git repository', sev: 'HIGH' as Severity },
    { path: '/.env', sig: /^[A-Z0-9_]+\s*=/m, name: 'Exposed .env file', sev: 'CRITICAL' as Severity },
    { path: '/.DS_Store', sig: /Bud1|\x00\x00\x00\x01Bud1/, name: 'Exposed .DS_Store', sev: 'LOW' as Severity },
    { path: '/server-status', sig: /Apache Server Status/i, name: 'Apache server-status exposed', sev: 'MEDIUM' as Severity },
    { path: '/actuator/env', sig: /"propertySources"|activeProfiles/i, name: 'Spring Actuator env exposed', sev: 'HIGH' as Severity },
];

export const exposedServices: Scenario = {
    id: 'exposed-services',
    name: 'Exposed Services & Files',
    description: 'Flag sensitive services and leaked files (.git, .env, actuator) reachable from the internet.',
    category: 'EXPOSURE',
    maxSeverity: 'CRITICAL',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1190 Exploit Public-Facing Application',
    requiresActive: false,
    intrusive: true,
    tags: ['exposure', 'misconfig', 'secrets'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);

        for (const s of services) {
            const sens = SENSITIVE_PORTS[s.port];
            if (sens) {
                results.push({
                    title: `${sens.name} exposed on ${s.ip}:${s.port}`,
                    severity: sens.severity,
                    outcome: 'VULNERABLE',
                    target: `${s.ip}:${s.port}`,
                    attckTactic: 'Initial Access',
                    attckTechnique: 'T1190 Exploit Public-Facing Application',
                    evidence: `${sens.name} is reachable from the internet (${sens.why}).${s.banner ? ' Banner: ' + s.banner.slice(0, 120) : ''}`,
                    remediation: sens.remediation,
                });
            }
        }

        // Read-only GET probes for leaked files on web targets. We confirm
        // existence and redact any contents, never echoing secret values.
        for (const w of webTargetsFrom(services)) {
            for (const f of EXPOSED_FILES) {
                const probe = await httpGet(w.url + f.path, { maxBody: 2048, timeout: 5000 });
                if (probe.ok && probe.status === 200 && f.sig.test(probe.bodySnippet)) {
                    const lineCount = probe.bodySnippet.split('\n').filter(Boolean).length;
                    results.push({
                        title: `${f.name} at ${w.host}:${w.port}`,
                        severity: f.sev,
                        outcome: 'VULNERABLE',
                        target: w.url + f.path,
                        attckTactic: 'Initial Access',
                        attckTechnique: 'T1083 File and Directory Discovery',
                        // Evidence is redacted: we prove reachability, not the secrets.
                        evidence: `HTTP 200 and the response matches the ${f.name} signature. ${lineCount} line(s) present (contents redacted).`,
                        remediation: `Block public access to ${f.path}. Rotate any credentials that may have been exposed.`,
                    });
                }
            }
        }

        if (results.length === 0) {
            results.push({
                title: 'No exposed sensitive services or files',
                severity: 'INFO',
                outcome: 'SECURE',
                target: ctx.target,
                evidence: 'No sensitive ports or leaked files found in the reachable surface.',
            });
        }
        return results;
    },
};
