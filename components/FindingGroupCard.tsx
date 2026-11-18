"use client";

import { useState } from 'react';
import { AlertTriangle, ChevronDown, ShieldCheck } from 'lucide-react';
import { SeverityBadge } from '@/components/ui';
import { splitList, type Finding } from '@/components/FindingCard';
import type { FindingGroup } from '@/lib/group-findings';
import { formatDateTime, portLabel, severityBar } from '@/lib/ui';

function HostRow({ finding }: { finding: Finding }) {
    const [open, setOpen] = useState(false);
    const domains = splitList(finding.domains, ',');
    const panelId = `host-${finding.id}`;
    return (
        <li className="border-t border-border first:border-t-0">
            <button
                type="button"
                onClick={() => setOpen(!open)}
                aria-expanded={open}
                aria-controls={panelId}
                className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-left transition-colors hover:bg-accent/60 sm:px-5"
            >
                <span className="font-mono text-sm">{finding.ip}</span>
                {finding.version && <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-[11px] text-muted-foreground">{/^v/i.test(finding.version) ? finding.version : `v${finding.version}`}</span>}
                {domains.length > 0 && (
                    <span className="min-w-0 truncate text-xs text-muted-foreground">{domains.slice(0, 2).join(', ')}{domains.length > 2 ? ` +${domains.length - 2}` : ''}</span>
                )}
                <span className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
                    {finding.closedAt
                        ? <span className="rounded-full bg-muted px-2 py-0.5 font-medium">Closed {formatDateTime(finding.closedAt)}</span>
                        : <span>Seen {formatDateTime(finding.updatedAt)}</span>}
                    <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden />
                </span>
            </button>
            {open && (
                <div id={panelId} className="space-y-3 bg-background/40 px-4 pb-4 pt-1 sm:px-5">
                    {finding.vulnerability && (
                        <p className="text-sm"><span className="font-medium">Issues on this host: </span>{splitList(finding.vulnerability, ';').join('; ')}</p>
                    )}
                    <div>
                        <p className="mb-1.5 text-xs font-semibold text-muted-foreground">Evidence</p>
                        <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-background p-3 font-mono text-xs leading-relaxed text-muted-foreground">
                            {finding.forensics || 'No discovery log recorded.'}
                        </pre>
                    </div>
                    {finding.banner && (
                        <div>
                            <p className="mb-1.5 text-xs font-semibold text-muted-foreground">Raw banner</p>
                            <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-background p-3 font-mono text-xs text-muted-foreground">{finding.banner}</pre>
                        </div>
                    )}
                </div>
            )}
        </li>
    );
}

/** One card per issue. The affected hosts are listed only when the card is opened. */
export default function FindingGroupCard({ group }: { group: FindingGroup<Finding> }) {
    const [open, setOpen] = useState(false);
    const total = group.findings.length;
    const share = (hosts: number) => (total > 1 && hosts < total ? ` (${hosts} of ${total} hosts)` : '');
    const panelId = `group-${group.key.replace(/[^a-z0-9]/gi, '-')}`;

    return (
        <article className="flex overflow-hidden rounded-2xl border border-border bg-card">
            <div className={`w-1 shrink-0 ${severityBar[group.severity] ?? severityBar.INFO}`} aria-hidden />
            <div className="min-w-0 flex-1">
                <div className="p-4 sm:p-5">
                    <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-semibold">
                            {group.service}
                            <span className="font-normal text-muted-foreground"> on port {portLabel(group.port, group.protocol)}</span>
                        </h3>
                        <SeverityBadge severity={group.severity} />
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                        {total === 1 ? <span className="font-mono text-foreground">{group.findings[0].ip}</span> : `${total} hosts`}
                        <span className="ml-3">Last seen {formatDateTime(group.lastSeen)}</span>
                    </p>

                    {group.description && <p className="mt-3 break-words text-sm text-muted-foreground">{group.description}</p>}

                    {group.issues.length > 0 && (
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                            <div className="rounded-lg border border-border bg-background/60 p-3">
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                                    <AlertTriangle className="h-3.5 w-3.5 text-sev-critical" aria-hidden />
                                    {group.issues.length === 1 ? 'Issue' : `${group.issues.length} issues`}
                                </p>
                                <ul className="mt-2 space-y-1 text-sm">
                                    {group.issues.slice(0, 6).map((i) => <li key={i.text}>{i.text}<span className="text-muted-foreground">{share(i.hosts)}</span></li>)}
                                    {group.issues.length > 6 && <li className="text-muted-foreground">{group.issues.length - 6} more, see the hosts below</li>}
                                </ul>
                            </div>
                            <div className="rounded-lg border border-border bg-background/60 p-3">
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                                    <ShieldCheck className="h-3.5 w-3.5 text-success" aria-hidden />
                                    Recommended action
                                </p>
                                {group.remediations.length > 0 ? (
                                    <ul className="mt-2 space-y-2 text-sm">
                                        {group.remediations.slice(0, 3).map((r) => <li key={r.text}>{r.text}</li>)}
                                    </ul>
                                ) : (
                                    <p className="mt-2 text-sm">Restrict access to this port with a firewall and keep the software on a supported release.</p>
                                )}
                            </div>
                        </div>
                    )}
                </div>

                <button
                    type="button"
                    onClick={() => setOpen(!open)}
                    aria-expanded={open}
                    aria-controls={panelId}
                    className="flex w-full items-center justify-between border-t border-border px-4 py-3 text-sm font-medium transition-colors hover:bg-accent/60 sm:px-5"
                >
                    Affected hosts ({total})
                    <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden />
                </button>
                {open && (
                    <ul id={panelId} className="max-h-[32rem] overflow-y-auto border-t border-border">
                        {group.findings.map((f) => <HostRow key={f.id} finding={f} />)}
                    </ul>
                )}
            </div>
        </article>
    );
}
