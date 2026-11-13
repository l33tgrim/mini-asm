#!/usr/bin/env tsx
/**
 * Mini ASM breach-simulation CLI.
 *
 * Emits JSON so an agent (or CI) can drive an engagement end to end. Every
 * active action passes through the same safety gates as the web app.
 *
 *   npm run miniasm -- scenarios
 *   npm run miniasm -- engagement:create --name "Acme Q4" --mode ACTIVE
 *   npm run miniasm -- engagement:scope --engagement <id> --add acme.com --add 10.0.0.0/24
 *   npm run miniasm -- engagement:verify --engagement <id>
 *   npm run miniasm -- engagement:authorize --engagement <id> --by "jane@acme"
 *   npm run miniasm -- playbook external-footprint --target acme.com --engagement <id>
 *   npm run miniasm -- report --engagement <id> --md
 */
import { prisma } from '@/lib/prisma';
import { scenarioCatalog, listPlaybooks } from '@/lib/engine/registry';
import { runScenario, runPlaybook, runSteps, type EngagementContext } from '@/lib/engine/runner';
import { loadEngagementContext, persistRun, loadCustomPlaybook } from '@/lib/engine/persist';
import { runAutopilot } from '@/lib/engine/autopilot';
import {
    generateVerifyToken,
    verifyDomainOwnership,
    classifyScope,
    listAllowedCommands,
    audit,
} from '@/lib/safety';
import { buildReport, reportSummaryJson, type ReportInput } from '@/lib/report/generate';
import { generateScenarioSpec, scaffoldScenarioFile } from '@/lib/ai/scenarioGenerator';
import type { Mode } from '@/lib/engine/types';
import fs from 'fs';

function parseArgs(argv: string[]) {
    const positional: string[] = [];
    const flags: Record<string, string | string[] | boolean> = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a.startsWith('--')) {
            const key = a.slice(2);
            const next = argv[i + 1];
            if (!next || next.startsWith('--')) {
                flags[key] = true;
            } else {
                if (flags[key] === undefined) flags[key] = next;
                else if (Array.isArray(flags[key])) (flags[key] as string[]).push(next);
                else flags[key] = [flags[key] as string, next];
                i++;
            }
        } else {
            positional.push(a);
        }
    }
    return { positional, flags };
}

function asArray(v: string | string[] | boolean | undefined): string[] {
    if (v === undefined || typeof v === 'boolean') return [];
    return Array.isArray(v) ? v : [v];
}

function out(obj: unknown) {
    console.log(JSON.stringify(obj, null, 2));
}

async function main() {
    const { positional, flags } = parseArgs(process.argv.slice(2));
    const cmd = positional[0];
    const engagementId = flags.engagement as string | undefined;
    const mode = (flags.mode as Mode | undefined) || undefined;

    switch (cmd) {
        case 'scenarios':
            out(scenarioCatalog());
            break;

        case 'playbooks':
            out(listPlaybooks());
            break;

        case 'commands':
            out(listAllowedCommands());
            break;

        case 'token':
            out({ token: generateVerifyToken() });
            break;

        case 'verify': {
            const domain = positional[1];
            const token = positional[2];
            if (!domain || !token) throw new Error('usage: verify <domain> <token>');
            out(await verifyDomainOwnership(domain, token));
            break;
        }

        case 'engagement:create': {
            const name = flags.name as string;
            if (!name) throw new Error('--name is required');
            const eng = await prisma.engagement.create({
                data: {
                    name,
                    description: (flags.description as string) || null,
                    mode: (mode as string) || 'SAFE',
                    status: 'DRAFT',
                },
            });
            await audit({ engagementId: eng.id, action: 'ENGAGEMENT_CREATED', detail: `name=${name} mode=${eng.mode}`, actor: 'cli' });
            out(eng);
            break;
        }

        case 'engagement:scope': {
            if (!engagementId) throw new Error('--engagement is required');
            const adds = asArray(flags.add);
            if (adds.length === 0) throw new Error('--add <value> is required');
            const created = [];
            for (const value of adds) {
                const kind = classifyScope(value);
                const verifyToken = kind === 'DOMAIN' ? generateVerifyToken() : null;
                const entry = await prisma.scopeEntry.upsert({
                    where: { engagementId_value: { engagementId, value } },
                    update: {},
                    create: { engagementId, value, kind, verifyToken, verified: kind !== 'DOMAIN' ? false : false },
                });
                created.push({
                    ...entry,
                    hint: kind === 'DOMAIN'
                        ? `Publish TXT _miniasm-auth.${value} = "${verifyToken}" OR host it at ${value}/.well-known/miniasm-auth.txt, then run engagement:verify`
                        : 'IP/CIDR scope must be authorized out of band by an operator (engagement:authorize).',
                });
            }
            await audit({ engagementId, action: 'SCOPE_ADDED', detail: adds.join(', '), actor: 'cli' });
            out(created);
            break;
        }

        case 'engagement:verify': {
            if (!engagementId) throw new Error('--engagement is required');
            const entries = await prisma.scopeEntry.findMany({ where: { engagementId, kind: 'DOMAIN' } });
            const report = [];
            for (const e of entries) {
                if (!e.verifyToken) continue;
                const res = await verifyDomainOwnership(e.value, e.verifyToken);
                if (res.verified) {
                    await prisma.scopeEntry.update({
                        where: { id: e.id },
                        data: { verified: true, verifyMethod: res.method, verifiedAt: new Date() },
                    });
                }
                await audit({ engagementId, action: res.verified ? 'OWNERSHIP_VERIFIED' : 'OWNERSHIP_FAILED', target: e.value, detail: res.detail, actor: 'cli' });
                report.push({ value: e.value, ...res });
            }
            out(report);
            break;
        }

        case 'engagement:authorize': {
            if (!engagementId) throw new Error('--engagement is required');
            const by = (flags.by as string) || 'cli-operator';
            // Domains must be token-verified before authorization.
            const unverifiedDomains = await prisma.scopeEntry.findMany({
                where: { engagementId, kind: 'DOMAIN', verified: false },
            });
            if (unverifiedDomains.length > 0 && !flags.force) {
                throw new Error(
                    `cannot authorize: ${unverifiedDomains.length} domain(s) not ownership-verified (${unverifiedDomains.map((d) => d.value).join(', ')}). Run engagement:verify first, or pass --force to attest.`
                );
            }
            // IP/CIDR entries (and forced domains) are attested by the operator.
            await prisma.scopeEntry.updateMany({
                where: { engagementId, OR: [{ kind: 'IP' }, { kind: 'CIDR' }, ...(flags.force ? [{ kind: 'DOMAIN' as const }] : [])] },
                data: { verified: true, verifyMethod: 'OPERATOR_ATTESTATION', verifiedAt: new Date() },
            });
            const eng = await prisma.engagement.update({
                where: { id: engagementId },
                data: { status: 'AUTHORIZED', authorizedBy: by, authorizedAt: new Date() },
            });
            await audit({ engagementId, action: 'ENGAGEMENT_AUTHORIZED', detail: `by=${by} force=${!!flags.force}`, actor: by });
            out(eng);
            break;
        }

        case 'engagement:show': {
            if (!engagementId) throw new Error('--engagement is required');
            const eng = await prisma.engagement.findUnique({
                where: { id: engagementId },
                include: { scope: true, runs: { orderBy: { createdAt: 'desc' }, take: 20 } },
            });
            out(eng);
            break;
        }

        case 'run': {
            const scenarioId = positional[1];
            const target = flags.target as string;
            if (!scenarioId || !target) throw new Error('usage: run <scenarioId> --target <t> --engagement <id> [--params <json>]');
            const params = flags.params ? JSON.parse(flags.params as string) : {};
            const { eng } = await buildContext(engagementId, mode, target);
            const result = await runScenario(scenarioId, target, eng, {}, params);
            if (engagementId) await persistRun(engagementId, result);
            out(result);
            break;
        }

        case 'playbook': {
            const target = flags.target as string;
            if (!target) throw new Error('usage: playbook <playbookId> --target <t> | playbook --custom <id> --target <t>');
            const { eng } = await buildContext(engagementId, mode, target);
            if (flags.custom) {
                const pb = await loadCustomPlaybook(flags.custom as string);
                const runs = await runSteps(pb.steps, target, eng);
                if (engagementId) for (const r of runs) await persistRun(engagementId, r, pb.id);
                out({ playbookId: pb.id, playbookName: pb.name, runs });
            } else {
                const playbookId = positional[1];
                if (!playbookId) throw new Error('provide a built-in playbook id or --custom <id>');
                const result = await runPlaybook(playbookId, target, eng);
                if (engagementId) for (const r of result.runs) await persistRun(engagementId, r, playbookId);
                out(result);
            }
            break;
        }

        case 'playbook:create': {
            const name = flags.name as string;
            if (!name) throw new Error('--name is required');
            const pb = await prisma.customPlaybook.create({
                data: {
                    name,
                    description: (flags.description as string) || null,
                    threat: (flags.threat as string) || null,
                    attckTactics: (flags.tactics as string) || null,
                },
            });
            out(pb);
            break;
        }

        case 'playbook:step': {
            const playbookId = flags.playbook as string;
            const scenarioId = flags.scenario as string;
            if (!playbookId || !scenarioId) throw new Error('usage: playbook:step --playbook <id> --scenario <scenarioId> [--params <json>] [--order <n>]');
            if (flags.params) JSON.parse(flags.params as string); // validate
            const step = await prisma.playbookStep.create({
                data: {
                    playbookId,
                    scenarioId,
                    order: flags.order ? Number(flags.order) : 0,
                    params: (flags.params as string) || null,
                },
            });
            out(step);
            break;
        }

        case 'playbook:list': {
            const pbs = await prisma.customPlaybook.findMany({
                orderBy: { createdAt: 'desc' },
                include: { steps: { orderBy: { order: 'asc' } } },
            });
            out(pbs);
            break;
        }

        case 'autorun': {
            const target = flags.target as string;
            if (!target) throw new Error('usage: autorun --target <t> --engagement <id> [--mode ACTIVE]');
            const { eng } = await buildContext(engagementId, mode, target);
            const result = await runAutopilot(target, eng);
            if (engagementId) for (const r of result.runs) await persistRun(engagementId, r, 'autopilot');
            out({
                target: result.target,
                mode: result.mode,
                plannedBy: result.plannedBy,
                risk: result.risk,
                narrative: result.narrative,
                scenarios: result.runs.map((r) => ({ scenario: r.scenarioName, status: r.status, summary: r.summary })),
            });
            break;
        }

        case 'report': {
            if (!engagementId) throw new Error('--engagement is required');
            const eng = await prisma.engagement.findUnique({
                where: { id: engagementId },
                include: { runs: { include: { results: true }, orderBy: { createdAt: 'asc' } } },
            });
            if (!eng) throw new Error('engagement not found');
            const input: ReportInput = {
                engagementName: eng.name,
                mode: eng.mode,
                runs: eng.runs.map((r) => ({
                    scenarioName: r.scenarioName,
                    target: r.target,
                    status: r.status,
                    results: r.results.map((x) => ({
                        title: x.title,
                        severity: x.severity as ReportInput['runs'][0]['results'][0]['severity'],
                        outcome: x.outcome as ReportInput['runs'][0]['results'][0]['outcome'],
                        attckTactic: x.attckTactic || undefined,
                        attckTechnique: x.attckTechnique || undefined,
                        target: x.target || undefined,
                        evidence: x.evidence || undefined,
                        remediation: x.remediation || undefined,
                    })),
                })),
            };
            if (flags.md) console.log(buildReport(input));
            else out(reportSummaryJson(input));
            break;
        }

        case 'scaffold': {
            const request = positional[1];
            if (!request) throw new Error('usage: scaffold "<threat description>"');
            const { spec, source, model } = await generateScenarioSpec(request);
            const fileSource = scaffoldScenarioFile(spec);
            if (flags.write) {
                fs.writeFileSync(flags.write as string, fileSource);
            }
            out({ source, model, spec, file: flags.write || null, preview: fileSource });
            break;
        }

        default:
            out({
                usage: [
                    'scenarios | playbooks | commands',
                    'token | verify <domain> <token>',
                    'engagement:create --name X [--mode SAFE|ACTIVE] [--description Y]',
                    'engagement:scope --engagement <id> --add <value> [--add <value>]',
                    'engagement:verify --engagement <id>',
                    'engagement:authorize --engagement <id> --by <name>',
                    'engagement:show --engagement <id>',
                    'run <scenarioId> --target <t> --engagement <id> [--mode ACTIVE] [--params <json>]',
                    'playbook <playbookId> --target <t> --engagement <id> [--mode ACTIVE]',
                    'playbook --custom <id> --target <t> --engagement <id>',
                    'playbook:create --name X [--threat T] [--description Y] [--tactics "a,b"]',
                    'playbook:step --playbook <id> --scenario <scenarioId> [--params <json>] [--order <n>]',
                    'playbook:list',
                    'autorun --target <t> --engagement <id> [--mode ACTIVE]   (AI autonomous assessment)',
                    'report --engagement <id> [--md]',
                    'scaffold "<threat description>" [--write lib/engine/scenarios/foo.ts]',
                ],
            });
    }
}

// Build a gate context. With an engagement id we load its real scope; without
// one (ad-hoc), only SAFE scenarios run and the single target is the scope,
// never verified, so active scenarios stay blocked.
async function buildContext(engagementId: string | undefined, mode: Mode | undefined, target: string): Promise<{ eng: EngagementContext }> {
    if (engagementId) {
        const { eng } = await loadEngagementContext(engagementId, mode, 'cli');
        return { eng };
    }
    return {
        eng: {
            engagementId: undefined,
            mode: mode || 'SAFE',
            scope: [{ value: target, kind: classifyScope(target), verified: false }],
            actor: 'cli-adhoc',
            authorized: false,
        },
    };
}

main()
    .catch((e) => {
        console.error(JSON.stringify({ error: (e as Error).message }));
        process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
