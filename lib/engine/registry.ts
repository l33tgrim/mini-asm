import type { Scenario, Playbook } from './types';
import { ALL_SCENARIOS } from './scenarios';
import { ALL_PLAYBOOKS } from './playbooks';

const scenarioMap = new Map<string, Scenario>();
for (const s of ALL_SCENARIOS) {
    if (scenarioMap.has(s.id)) {
        throw new Error(`Duplicate scenario id: ${s.id}`);
    }
    scenarioMap.set(s.id, s);
}

const playbookMap = new Map<string, Playbook>();
for (const p of ALL_PLAYBOOKS) {
    playbookMap.set(p.id, p);
}

export function getScenario(id: string): Scenario | undefined {
    return scenarioMap.get(id);
}

export function listScenarios(): Scenario[] {
    return Array.from(scenarioMap.values());
}

export function getPlaybook(id: string): Playbook | undefined {
    return playbookMap.get(id);
}

export function listPlaybooks(): Playbook[] {
    return Array.from(playbookMap.values());
}

/** Scenario catalog as plain data (for API / CLI listing). */
export function scenarioCatalog() {
    return listScenarios().map((s) => ({
        id: s.id,
        name: s.name,
        description: s.description,
        category: s.category,
        maxSeverity: s.maxSeverity,
        attckTactic: s.attckTactic,
        attckTechnique: s.attckTechnique,
        requiresActive: s.requiresActive,
        intrusive: s.intrusive,
        tags: s.tags ?? [],
        params: s.params ?? [],
    }));
}
