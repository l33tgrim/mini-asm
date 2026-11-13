# Writing and adding scenarios

A scenario is a self-contained, non-destructive check. The engine discovers it
through the registry, and the safety gate decides whether it may run. This is the
extension point for new breach and threat-led tests.

## The Scenario interface

See `lib/engine/types.ts`. A scenario is an object:

```ts
export const myScenario: Scenario = {
    id: 'my-scenario',              // kebab-case, unique
    name: 'Human readable name',
    description: 'What it checks.',
    category: 'EXPOSURE',           // RECON | EXPOSURE | VULN | WAF | PROOF | POSTURE
    maxSeverity: 'HIGH',
    attckTactic: 'Initial Access',
    attckTechnique: 'T1190 Exploit Public-Facing Application',
    requiresActive: true,           // true = needs authorized + verified scope
    intrusive: true,                // true = touches target beyond passive recon
    tags: ['example'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        // use ctx.target, ctx.mode, ctx.state, ctx.log
        return results;
    },
};
```

`requiresActive: true` means the scenario only runs on an authorized engagement
in ACTIVE mode against ownership-verified scope. Set it for anything that sends
attack-shaped traffic or interacts beyond passive recon.

## Rules for a scenario

- Non-destructive only. No writes, deletes, denial of service, or data copying.
- Use only the safe primitives in `lib/engine/primitives.ts`: `tcpConnect`,
  `grabBanner`, `httpGet`, `redisReadOnly`. These are rate-limited and honour the
  kill switch.
- Reuse recon with `ensureServices(ctx)` from `scenarios/_shared.ts` so a
  playbook scans once and every scenario shares the result.
- Return each result with an `outcome`: `SECURE`, `VULNERABLE`, `PROVEN`,
  `INFO`, or `ERROR`, plus a `remediation` where it helps.

## Adding one by hand

1. Create `lib/engine/scenarios/my-scenario.ts` exporting a `Scenario`.
2. Import it in `lib/engine/scenarios/index.ts` and add it to `ALL_SCENARIOS`.
3. It now appears in the catalog, the CLI, and the web app.

## Adding one with the AI generator

The generator drafts a spec and a ready-to-edit file skeleton. The generated
`run()` is a stub that does nothing until a human or the agent implements it, so
a scaffolded file can never execute un-reviewed logic.

```bash
npm run miniasm -- scaffold "test for exposed Jenkins script console" \
  --write lib/engine/scenarios/jenkins-console.ts
```

With `ANTHROPIC_API_KEY` set it uses Claude (Fable 5.2) to draft the spec;
without it you get a local template. Either way you implement `run()` with safe
primitives, then register it in `index.ts`.

## Playbooks

A playbook is an ordered bundle of scenarios that emulates a real threat. See
`lib/engine/playbooks.ts`. Recon runs first so later scenarios reuse its
discovery. Add a playbook by appending to `ALL_PLAYBOOKS`.

## Exec adapters (OS-level proof of command)

A generic RCE engine is intentionally not shipped. For a known, authorized weak
point in your own app, register an adapter in `lib/engine/adapters.ts`. It
receives an allowlisted command key and drives your specific path to run exactly
that benign command. Without a matching adapter, proof-of-command stays in
dry-run.
