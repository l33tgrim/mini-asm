# PayInc Security Validation (Mini ASM)

Attack surface management plus a non-destructive breach and attack simulation
(BAS) engine, for authorised testing of your own infrastructure.

It discovers what you expose to the internet, enriches findings with known CVEs,
measures WAF rule coverage, and proves reachability, command execution and data
access without breaking anything or copying data. The engine is driven from the
web app or from a JSON-speaking CLI that an agent can orchestrate.

Only test systems you own or have written authorisation to test.

## What it does

- Asset discovery: DNS, certificate logs, naming patterns, alias chains, address ownership, port and service mapping.
- Change tracking between scans of the same target.
- Exposure checks: sensitive services and leaked files (`.git`, `.env`, actuator).
- Posture: TLS and certificate health, HTTP security headers, SPF and DMARC.
- Vulnerabilities: service and version to CVE mapping with a CISA KEV flag.
- WAF: fingerprint, benign-canary rule coverage, origin-exposure detection.
- Proofs (non-destructive): reach, read-only command, metadata-only data read.
- Threat-led playbooks that chain scenarios, plus your own custom ones.
- Autonomous assessment: recon, an adaptive scenario plan, a posture score and a narrative.
- Scheduled scans that keep the inventory current.

Everything active is gated. See [docs/SAFETY.md](docs/SAFETY.md).

## Getting started

```bash
npm install
npm run db:migrate      # creates or updates prisma/dev.db
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000. For production use `npm run build` then `npm start`.

The database file is not kept in git. It is created by `npm run db:migrate`.

## Running in a container

```bash
cp .env.example .env            # set ASM_USERNAME and ASM_PASSWORD
docker compose up -d --build
```

Open http://localhost:3001. The image is a multi-stage build on the current
Node LTS Alpine base with the latest OS patches applied at build time. It runs
as a non-root user on a read-only filesystem with all Linux capabilities
dropped, and it has no package manager inside. The database lives on the
`asm-data` volume and migrations are applied each time the container starts.
To update to the latest version from GitHub, run `.\update.ps1` on Windows or
`./update.sh` elsewhere. It pulls the code, rebuilds with the newest base image
and restarts the container. Your data stays on the volume.

## Vulnerability checks

Port scanning is only the first step. The Vulnerability Assessment playbook
also runs:

- `cve-enrichment`: known CVEs for the service versions found on open ports.
- `web-tech-vulns`: web server, framework and front-end library versions with
  known vulnerabilities or no vendor support.
- `web-exposure-scan`: files and consoles that should not be public (`.git`,
  `.env`, debug pages, admin tools, API schemas). A hit is reported only when
  the content has the expected format, which confirms it without storing it.
- TLS, security headers, cookies, CORS, HTTP methods and directory listing.

Confirmation is always non-destructive. The proof scenarios (reach, command,
data) show that a weakness is real with a handshake, one read-only command or
metadata counts. See [docs/SAFETY.md](docs/SAFETY.md).

## Access control

The app opens on a sign-in page that checks `ASM_USERNAME` and `ASM_PASSWORD`.
Sessions last 12 hours, are signed, and end when the password changes. Scripts
can still send the same credentials as HTTP Basic auth on each request. Ten
failed sign-ins from one address lock it out for 15 minutes.

| Variable | Purpose |
| --- | --- |
| `ASM_USERNAME`, `ASM_PASSWORD` | Credentials for the sign-in page, also accepted as Basic auth by scripts |
| `ASM_SESSION_SECRET` | Optional key for signing sessions. Without it the key is derived from the credentials |
| `ASM_AUTH_DISABLED=true` | Runs without a login. Use only on a trusted local machine |

In production the app answers `503` until credentials are set or authentication is
explicitly disabled. In development it runs open when no credentials are set. Put the
app behind HTTPS when it is reachable over a network; the session cookie is marked
secure automatically when served over HTTPS. Cross-site write requests are always refused.

## Testing an asset from the attack surface

Each host and hostname on the Attack surface page has a Threat scenarios button. It
looks at what the scans found on that asset (web ports, TLS, data stores, whether it
is a hostname or an IP) and offers only the scenarios that apply, already ticked.
Pick an engagement whose scope covers the asset, add the asset to another
engagement's scope, or let it create a new SAFE engagement for it. The results land
on that engagement's page. Breach proofs are listed separately and stay locked
unless the engagement is authorised, in ACTIVE mode, and the asset is
ownership-verified, the same gates as everywhere else.

## Authorisation first

Nothing active runs without an authorised engagement and ownership-verified scope.

1. Create an engagement (SAFE or ACTIVE mode) and add scope: domains, IPv4 addresses
   or CIDR ranges of /24 or smaller. Loopback, link-local and reserved space is refused.
2. Prove you control each domain with a DNS TXT record or a well-known file. IP ranges
   are attested by the operator, and the attestation is recorded in the audit trail.
3. Authorise the engagement, then run a scenario, a playbook or the autonomous assessment.

An engagement's mode is a ceiling: a request can run an ACTIVE engagement in SAFE mode,
but can never raise a SAFE engagement to ACTIVE.

## CLI (agent-drivable)

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

Every command emits JSON (except `report --md`).

## Scans and schedules

A scan validates the target, maps it, then probes 50 common ports per host with
banner, HTTP header and TLS certificate checks.

For a domain the mapping follows what an outside attacker would do:

- DNS records: A, AAAA, NS, MX, SRV, SPF, DMARC and common DKIM selectors.
- Certificate transparency logs (crt.sh, then Cert Spotter) for every name that has
  ever had a public certificate.
- The certificate each discovered host presents, for sibling names.
- A common name list, plus names guessed from the naming pattern of what was found
  (`pay-uat` suggests `pay-dev`, `pay-dr`; `web1` suggests `web2`). With
  `ANTHROPIC_API_KEY` set, the model also proposes likely names and the hostnames
  found so far are sent to the Anthropic API for that.
- Alias chains, to show which cloud or SaaS platform sits behind each name.
- Stale names: names on certificates that no longer resolve. These feed the
  subdomain takeover check.
- Third parties: SaaS products revealed by verification records, mail senders in
  SPF, and the registry owner of each address block (rdap.org).
- Related domains that share a certificate or infrastructure record.

Only names under the target domain are scanned. Related domains, third-party hosts
and IPv6 addresses are reported but left alone. Each outside source fails soft, so a
scan still runs if one is unreachable. The server needs outbound HTTPS to crt.sh,
api.certspotter.com and rdap.org for those steps.

A finished scan is compared with the previous finished scan of the same target, and
the scan page lists new and closed services and hostnames that appeared or went away.

Limits: 256 IPs per scan, 3 scans at a time, 30 minutes per run (a stopped scan can
be resumed). Schedules run daily, weekly or monthly while the server is running.

## AI

Set `ANTHROPIC_API_KEY` to let Claude plan the autonomous assessment, write its
narrative and draft new scenarios (model set by `MINIASM_MODEL`). Without a key a
deterministic planner and a template are used. With a key, discovered service details
and finding summaries for the target are sent to the Anthropic API. The model can only
pick scenarios that exist, and every pick still passes the same safety gate.

## Architecture notes

- Next.js App Router, Prisma, SQLite.
- Scans and the scheduler run inside the Node server process (`lib/scan-runner.ts`,
  `lib/scheduler.ts`, started from `instrumentation.ts`), so the app needs a
  long-running server and not a serverless platform. Scans that were running when the
  server stopped are marked `INTERRUPTED` on the next start and can be resumed.
- `proxy.ts` handles authentication and rejects cross-site write requests.
- The BAS engine lives in `lib/engine`, its gates in `lib/safety`.
- The interface follows the PayInc corporate identity (Master Brand Manual, Oct 2025).
  Colours and type live in the `@theme` block of `app/globals.css`; severity and status
  chips use the data palette.

## Extending it

Add scenarios and playbooks per [docs/SCENARIOS.md](docs/SCENARIOS.md).

## Tests

```bash
npm test
```

Covers the safety gates: scope matching, the authorisation and verification
requirements for active scenarios, and the command allowlist.

## Stop everything

Set `MINIASM_KILL=1` or create a `.miniasm-stop` file at the project root to halt
all active actions immediately.

## Known limitations

- Detection is banner and header based. Treat findings as leads to verify.
- IPv4 only.
- The DNS reconnaissance summary on the attack surface page reflects the most recent domain scan.
- One shared login. There are no user accounts or roles, so audit entries name "web" or the CLI operator.
- Scenario runs happen inside the request that starts them (up to five minutes).
