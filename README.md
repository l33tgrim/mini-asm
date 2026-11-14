# Mini ASM

A small attack surface management tool. Give it a domain, an IPv4 address or a CIDR range and it
discovers hosts, probes 50 common ports, fingerprints the services it finds and records the issues.

Only scan systems you own or have written authorisation to test.

## Getting started

```bash
npm install
npm run db:migrate      # creates or updates prisma/dev.db
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

For production:

```bash
npm run build
npm start
```

## Access control

| Variable | Purpose |
| --- | --- |
| `ASM_USERNAME`, `ASM_PASSWORD` | Credentials for HTTP Basic authentication on every page and API route |
| `ASM_AUTH_DISABLED=true` | Runs without a login. Use only on a trusted local machine |

In production the app answers `503` until credentials are set or authentication is explicitly
disabled. In development it runs open when no credentials are set. Basic authentication sends the
password on every request, so put the app behind HTTPS when it is reachable over a network.

## What a scan does

1. **Target validation.** Domains, IPv4 addresses and CIDR ranges of /24 or smaller are accepted.
   Loopback, link-local and reserved addresses are refused, including when a domain resolves to them.
2. **Domain discovery.** A, CNAME, NS, MX, SPF and DMARC records, a subdomain word list (with
   wildcard DNS detection) and names from the TLS certificate. Name servers and mail servers are
   only scanned when they sit under the target domain, because they usually belong to a third party.
3. **Port probe.** TCP connect on 50 common ports per host, banner grab, HTTP header and TLS
   certificate checks.
4. **Findings.** One finding per IP and port, updated on every rescan.

Limits: 256 IPs per scan, 3 scans at a time, 30 minutes per run (a stopped scan can be resumed).

## Architecture notes

- Next.js App Router, Prisma, SQLite (`prisma/dev.db`).
- Scans and the scheduler run inside the Node server process (`lib/scan-runner.ts`,
  `lib/scheduler.ts`, started from `instrumentation.ts`). The app therefore needs a long-running
  server (`npm start`), not a serverless platform. Scans that were running when the server stopped
  are marked `INTERRUPTED` on the next start and can be resumed.
- `proxy.ts` handles authentication and rejects cross-site write requests.
- The interface follows the PayInc corporate identity (Master Brand Manual, Oct 2025). Colours and type
  live in the `@theme` block of `app/globals.css`; severity and status chips use the data palette.

## Known limitations

- Detection is banner and header based. Treat findings as leads to verify, not confirmed
  vulnerabilities.
- IPv4 only.
- The DNS reconnaissance summary is stored once, so it always reflects the most recent domain scan.
- One shared login. There are no user accounts or roles.
