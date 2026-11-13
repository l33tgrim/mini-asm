# Mini ASM

Attack Surface Management plus a non-destructive Breach and Attack Simulation
(BAS) engine, for authorized testing of your own infrastructure.

It discovers what you expose to the internet, enriches findings with known CVEs,
measures WAF rule coverage, and proves reachability, command execution, and data
access without breaking anything or copying data. The engine is driven from the
web app or from a JSON-speaking CLI that an agent can orchestrate.

## What it does

- Asset discovery: DNS, subdomains, certificate SANs, port and service mapping.
- Exposure checks: sensitive services and leaked files (`.git`, `.env`, actuator).
- Posture: TLS/certificate health, HTTP security headers, SPF/DMARC.
- Vulnerabilities: service/version to CVE mapping with a CISA KEV flag.
- WAF: fingerprint, benign-canary rule coverage, origin-exposure detection.
- Proofs (non-destructive): reach, read-only command, metadata-only data read.
- Threat-led playbooks that chain scenarios into an adversary narrative.

Everything active is gated. See [docs/SAFETY.md](docs/SAFETY.md).

## Authorization first

Nothing active runs without an authorized engagement and ownership-verified
scope. You prove you control a domain with a DNS TXT record or a well-known file;
IP ranges are attested by an operator. See the safety doc for details.

## Quickstart (web)

```bash
npm install
npx prisma migrate deploy   # or: npx prisma migrate dev
npm run dev
```

Open http://localhost:3000, go to Engagements, create one, add scope, verify
ownership, authorize, then run a scenario or playbook.

## Quickstart (CLI, agent-drivable)

```bash
npm run miniasm -- scenarios
npm run miniasm -- engagement:create --name "PayInc perimeter" --mode ACTIVE
npm run miniasm -- engagement:scope --engagement <id> --add payinc.com --add 203.0.113.0/24
# publish the printed token, then:
npm run miniasm -- engagement:verify --engagement <id>
npm run miniasm -- engagement:authorize --engagement <id> --by "you@payinc"
npm run miniasm -- playbook external-footprint --target payinc.com --engagement <id>
npm run miniasm -- report --engagement <id> --md
```

Every command emits JSON (except `report --md`), so an agent can run the whole
engagement and read the results back.

## AI

The scenario generator drafts new scenarios. Set `ANTHROPIC_API_KEY` to use
Claude (Fable 5.2, override with `MINIASM_MODEL`); without a key it produces a
local template. Generated scenarios are proposals: a human or the agent
implements and reviews the logic before it runs. The agent can also drive the
CLI directly with no key wired in.

## Extending it

Add scenarios and playbooks per [docs/SCENARIOS.md](docs/SCENARIOS.md).

## Tests

```bash
npm test
```

Covers the safety gates: scope matching, the authorization and verification
requirements for active scenarios, and the command allowlist.

## Stop everything

Set `MINIASM_KILL=1` or create a `.miniasm-stop` file at the project root to halt
all active actions immediately.
