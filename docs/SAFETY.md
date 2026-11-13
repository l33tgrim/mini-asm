# Safety model

Mini ASM runs breach and attack simulations against your own, authorized
infrastructure. Everything active is non-destructive and gated. This document
describes the controls and why they exist.

## The gate

Every scenario execution passes through one choke point, `evaluateGate` in
`lib/engine/runner.ts`. It runs in the web app and the CLI, identically. A
scenario runs only if all of these hold:

1. The global kill switch is off.
2. The target is inside the engagement's scope.
3. For an active scenario, the engagement is authorized, in ACTIVE mode, and the
   matched scope entry is ownership-verified.

If any check fails, the scenario is marked BLOCKED, the reason is recorded in the
audit trail, and nothing touches the target.

## Scope

An engagement holds a list of scope entries: domains, IPs, or CIDRs. A target is
in scope if it is a scoped domain or a subdomain of one, an IP that equals a
scoped IP or sits inside a scoped CIDR, or an exact CIDR match. Anything else is
refused, recon included.

## Ownership verification

Before an active scenario may touch a domain, you prove you control it. The tool
issues a token and checks for it in one of two places:

- DNS TXT record: `_miniasm-auth.<domain>`
- Well-known file: `https://<domain>/.well-known/miniasm-auth.txt`

IP and CIDR scope cannot be proven this way, so an operator attests to them when
authorizing the engagement (recorded with who and when). This is the "test that
confirms authorization" and mirrors how commercial scanners verify domains.

## SAFE vs ACTIVE

- SAFE scenarios: recon, posture, vulnerability detection. Read-only, run on any
  in-scope target.
- ACTIVE scenarios: reach, command, and data proofs. Run only on an authorized
  engagement against verified scope.

## Non-destructive guarantees

- Proof of reach: a TCP handshake only. No payload is sent.
- Proof of command: against unauthenticated services we run ONE read-only server
  command (Redis `INFO`, Docker `GET /version`, Elasticsearch `GET /`) and
  capture the output. OS-level command execution happens only through an
  operator-supplied exec adapter for a known weak point in your own app, and even
  then only a command from the allowlist (`id`, `whoami`, `hostname`, `uname -a`,
  `pwd`). With no adapter registered, it runs nothing and reports dry-run.
- Proof of data: we return metadata only (key counts, index names and document
  counts, container lists). We never SELECT, dump, or copy records.
- WAF testing: benign canary payloads that do nothing even if they reach the app.
  We measure which categories the WAF blocks, we do not exploit.

## Operational controls

- Kill switch: set `MINIASM_KILL=1` or create a `.miniasm-stop` file at the
  project root to halt every active action immediately.
- Rate limiting: a per-host token bucket (`MINIASM_RATE_PER_SEC`, default 8)
  keeps traffic polite.
- Audit trail: every gate decision and active action is written to the
  `AuditLog` table and the engagement view.

## Command allowlist

The proof-of-command allowlist lives in `lib/safety/commandAllowlist.ts`.
Scenarios reference a command by key, never by a raw string, so there is no path
to arbitrary command construction. Destructive tokens are rejected as defence in
depth.
