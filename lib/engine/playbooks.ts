import type { Playbook } from './types';

/**
 * Threat-led playbooks: ordered bundles of scenarios that emulate how a real
 * adversary would approach the target. Recon always runs first so later
 * scenarios reuse its discovery. Add new playbooks here.
 */
export const ALL_PLAYBOOKS: Playbook[] = [
    {
        id: 'external-footprint',
        name: 'External Footprint (safe)',
        description: 'Baseline, fully non-intrusive view of internet exposure and posture. Runs in SAFE mode.',
        threat: 'Opportunistic scanning / pre-attack reconnaissance',
        scenarioIds: ['recon-exposure', 'exposed-services', 'tls-posture', 'security-headers', 'email-posture', 'cve-enrichment'],
        attckTactics: ['Reconnaissance', 'Initial Access'],
    },
    {
        id: 'ransomware-precursors',
        name: 'Ransomware Precursors',
        description: 'The exposed entry points ransomware crews use: RDP/SMB exposure, outdated services, reachable management surfaces.',
        threat: 'Ransomware affiliate initial access',
        scenarioIds: ['recon-exposure', 'exposed-services', 'cve-enrichment', 'proof-of-reach'],
        attckTactics: ['Initial Access', 'Discovery', 'Lateral Movement'],
    },
    {
        id: 'data-exposure-path',
        name: 'Data Exposure Path',
        description: 'Chase the path to data: unauthenticated stores, reach, and a metadata-only read proof. Never copies records.',
        threat: 'Data breach via exposed datastore',
        scenarioIds: ['recon-exposure', 'exposed-services', 'proof-of-reach', 'proof-of-command', 'proof-of-data'],
        attckTactics: ['Discovery', 'Execution', 'Collection'],
    },
    {
        id: 'perimeter-bypass',
        name: 'Perimeter / WAF Bypass',
        description: 'Measure WAF rule coverage with benign canaries and hunt for origin exposure that bypasses the WAF entirely.',
        threat: 'Application attacker evading edge defences',
        scenarioIds: ['recon-exposure', 'security-headers', 'waf-detect-bypass'],
        attckTactics: ['Defense Evasion', 'Initial Access'],
    },
];
