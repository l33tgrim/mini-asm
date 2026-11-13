export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// SECURE   = control held / nothing found
// VULNERABLE = weakness confirmed (no proof executed)
// PROVEN   = non-destructive proof obtained (reached it / ran a read command / read metadata)
// INFO     = informational discovery
// ERROR    = scenario could not complete
export type Outcome = 'SECURE' | 'VULNERABLE' | 'PROVEN' | 'INFO' | 'ERROR';

export type ScenarioCategory = 'RECON' | 'EXPOSURE' | 'VULN' | 'WAF' | 'PROOF' | 'POSTURE';

export type Mode = 'SAFE' | 'ACTIVE';

export interface ScenarioResult {
    title: string;
    severity: Severity;
    outcome: Outcome;
    attckTactic?: string;
    attckTechnique?: string;
    target?: string;
    evidence?: string;
    remediation?: string;
}

export interface RunContext {
    target: string;
    mode: Mode;
    engagementId?: string;
    // Shared bag so later scenarios reuse earlier recon (open ports, subdomains...).
    state: Record<string, unknown>;
    log: (msg: string) => void;
}

export interface Scenario {
    id: string;
    name: string;
    description: string;
    category: ScenarioCategory;
    maxSeverity: Severity;
    attckTactic?: string;
    attckTechnique?: string;
    /**
     * SAFE scenarios (recon, posture, vuln detection) run in any mode.
     * requiresActive scenarios (reach/command/data proofs) run ONLY when the
     * engagement is in ACTIVE mode against an ownership-verified target.
     */
    requiresActive: boolean;
    /** True if the scenario touches the target beyond passive recon. */
    intrusive: boolean;
    tags?: string[];
    run: (ctx: RunContext) => Promise<ScenarioResult[]>;
}

export interface Playbook {
    id: string;
    name: string;
    description: string;
    /** Real-world threat this playbook emulates. */
    threat: string;
    scenarioIds: string[];
    attckTactics: string[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
    INFO: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
};

export function maxSeverity(a: Severity, b: Severity): Severity {
    return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}
