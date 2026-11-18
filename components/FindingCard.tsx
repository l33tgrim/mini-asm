"use client";

import { useState } from 'react';
import { AlertTriangle, ChevronDown, ShieldCheck } from 'lucide-react';
import { SeverityBadge } from '@/components/ui';
import { formatDateTime, severityBar, portLabel } from '@/lib/ui';

export interface Finding {
    id: string;
    ip: string;
    port: number;
    protocol?: string;
    service: string | null;
    version: string | null;
    banner: string | null;
    severity: string;
    description: string | null;
    vulnerability: string | null;
    remediation: string | null;
    forensics: string | null;
    upstreamVersion: string | null;
    domains: string | null;
    techStack: string | null;
    closedAt?: string | null;
    updatedAt: string;
}

export const splitList = (value: string | null, separator: string) =>
    (value || '').split(separator).map((v) => v.trim()).filter(Boolean);

export default function FindingCard({ finding }: { finding: Finding }) {
    const [open, setOpen] = useState(false);
    const issues = splitList(finding.vulnerability, ';');
    const domains = splitList(finding.domains, ',');
    const tech = splitList(finding.techStack, ',');
    const panelId = `finding-${finding.id}`;

    return (
        <article className="flex overflow-hidden rounded-2xl border border-border bg-card">
            <div className={`w-1 shrink-0 ${severityBar[finding.severity] ?? severityBar.INFO}`} aria-hidden />
            <div className="min-w-0 flex-1">
                <div className="p-4 sm:p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                                <h3 className="font-semibold">
                                    {finding.service || 'Unknown service'}
                                    <span className="font-normal text-muted-foreground"> on port {portLabel(finding.port, finding.protocol)}</span>
                                </h3>
                                <SeverityBadge severity={finding.severity} />
                                {finding.version && (
                                    <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-[11px] text-muted-foreground">v{finding.version}</span>
                                )}
                            </div>
                            <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                                <span className="font-mono text-foreground">{finding.ip}</span>
                                {domains.length > 0 && (
                                    <span className="truncate">{domains.slice(0, 3).join(', ')}{domains.length > 3 ? ` +${domains.length - 3} more` : ''}</span>
                                )}
                                <span>Last seen {formatDateTime(finding.updatedAt)}</span>
                            </p>
                        </div>
                        <button
                            type="button"
                            onClick={() => setOpen(!open)}
                            aria-expanded={open}
                            aria-controls={panelId}
                            className="flex shrink-0 items-center gap-1.5 rounded-full border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                        >
                            Evidence
                            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden />
                        </button>
                    </div>

                    {finding.description && <p className="mt-3 break-words text-sm text-muted-foreground">{finding.description}</p>}

                    {issues.length > 0 && (
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                            <div className="rounded-lg border border-border bg-background/60 p-3">
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                                    <AlertTriangle className="h-3.5 w-3.5 text-sev-critical" aria-hidden />
                                    {issues.length === 1 ? 'Issue' : `${issues.length} issues`}
                                </p>
                                <ul className="mt-2 space-y-1 text-sm">
                                    {issues.map((issue) => <li key={issue}>{issue}</li>)}
                                </ul>
                            </div>
                            <div className="rounded-lg border border-border bg-background/60 p-3">
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                                    <ShieldCheck className="h-3.5 w-3.5 text-success" aria-hidden />
                                    Recommended action
                                </p>
                                <p className="mt-2 text-sm">
                                    {finding.remediation || 'Restrict access to this port with a firewall and keep the software on a supported release.'}
                                </p>
                                {finding.upstreamVersion && (
                                    <p className="mt-1 text-xs text-muted-foreground">Fixed in {finding.upstreamVersion}</p>
                                )}
                            </div>
                        </div>
                    )}

                    {tech.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                            {tech.map((t) => (
                                <span key={t} className="rounded-full border border-border bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">{t}</span>
                            ))}
                        </div>
                    )}
                </div>

                {open && (
                    <div id={panelId} className="space-y-4 border-t border-border bg-background/40 p-4 sm:p-5">
                        <div>
                            <p className="mb-2 text-xs font-semibold text-muted-foreground">Discovery log</p>
                            <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-background p-3 font-mono text-xs leading-relaxed text-muted-foreground">
                                {finding.forensics || 'No discovery log recorded.'}
                            </pre>
                        </div>
                        <div>
                            <p className="mb-2 text-xs font-semibold text-muted-foreground">Raw banner</p>
                            <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-background p-3 font-mono text-xs text-muted-foreground">
                                {finding.banner || 'The service did not return a banner.'}
                            </pre>
                        </div>
                    </div>
                )}
            </div>
        </article>
    );
}
