import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getTargetIps, scanIp } from '@/lib/scanner';

// Background scan runner
async function runBackgroundScan(scanId: string, mappings: Record<string, string[]> = {}) {
    console.log(`[SCAN ${scanId}] Background task started`);
    const scan = await prisma.scan.findUnique({
        where: { id: scanId }
    }) as any;

    if (!scan || !scan.ipList) {
        console.error(`[SCAN ${scanId}] Critical: Scan or ipList not found`);
        return;
    }

    const ips = JSON.parse(scan.ipList) as string[];
    const startTime = Date.now();
    const TIMEOUT_MS = 30 * 60 * 1000;
    try {
        await prisma.scan.update({
            where: { id: scanId },
            data: { status: 'RUNNING', startedAt: new Date() }
        });

        for (let i = scan.currentIndex; i < ips.length; i++) {
            const ip = ips[i];

            if (Date.now() - startTime > TIMEOUT_MS) {
                await prisma.scan.update({
                    where: { id: scanId },
                    data: { status: 'TIMED_OUT' }
                });
                return;
            }

            console.log(`[SCAN ${scanId}] [${i + 1}/${ips.length}] Probing ${ip}...`);
            const hostname = mappings[ip] && mappings[ip].length > 0 ? mappings[ip][0] : undefined;

            let results: any[] = [];
            try {
                results = await scanIp(ip, hostname);
            } catch (ipError: any) {
                console.error(`[SCAN ${scanId}] Error scanning IP ${ip}:`, ipError.message || ipError);
                // Continue to next IP instead of crashing the whole scan
            }

            // Skip IPs with no responding services
            if (results.length === 0) {
                console.log(`[SCAN ${scanId}] [${i + 1}/${ips.length}] No open ports on ${ip}, skipping...`);
                await prisma.scan.update({
                    where: { id: scanId },
                    data: { currentIndex: i + 1 }
                });
                continue;
            }

            for (const f of results) {
                try {
                    const targetLower = scan.target.toLowerCase();
                    const isDomain = !/^[0-9.]+$/.test(targetLower) && !targetLower.includes('/');

                    // Get existing to merge domains
                    const existing = await prisma.finding.findUnique({
                        where: { ip_port: { ip: f.ip, port: f.port } }
                    }) as any;

                    let domainsSet = new Set((existing?.domains || '').split(',').filter(Boolean).map((d: string) => d.toLowerCase()));

                    // Add current target if it's a domain
                    if (isDomain) domainsSet.add(targetLower);

                    // Add any discovery mappings found during resolution
                    if (mappings[f.ip]) {
                        mappings[f.ip].forEach((d: string) => domainsSet.add(d.toLowerCase()));
                    }

                    const domains = Array.from(domainsSet).join(',');

                    await prisma.finding.upsert({
                        where: { ip_port: { ip: f.ip, port: f.port } },
                        update: {
                            service: f.service,
                            version: f.version,
                            banner: f.banner,
                            severity: f.severity,
                            description: f.description,
                            vulnerability: f.vulnerability,
                            remediation: f.remediation,
                            forensics: f.forensics,
                            upstreamVersion: f.upstreamVersion,
                            domains: domains || null,
                            techStack: f.techStack || null,
                            scans: { connect: { id: scanId } },
                        },
                        create: {
                            ip: f.ip,
                            port: f.port,
                            service: f.service,
                            version: f.version,
                            banner: f.banner,
                            severity: f.severity,
                            description: f.description,
                            vulnerability: f.vulnerability,
                            remediation: f.remediation,
                            forensics: f.forensics,
                            upstreamVersion: f.upstreamVersion,
                            domains: domains || null,
                            techStack: f.techStack || null,
                            scans: { connect: { id: scanId } },
                        },
                    });
                } catch (findingError) {
                    console.error(`[SCAN ${scanId}] Error saving finding for ${f.ip}:${f.port}:`, findingError);
                }
            }

            await prisma.scan.update({
                where: { id: scanId },
                data: { currentIndex: i + 1 }
            });
        }

        await prisma.scan.update({
            where: { id: scanId },
            data: { status: 'COMPLETED', completedAt: new Date() }
        });
        console.log(`[SCAN ${scanId}] Finished successfully`);
    } catch (error: any) {
        console.error(`[SCAN ${scanId}] CRITICAL SCAN ERROR:`, error);
        await prisma.scan.update({
            where: { id: scanId },
            data: { status: 'FAILED' }
        });
    }
}

export async function GET() {
    try {
        const scans = await prisma.scan.findMany({
            orderBy: { createdAt: 'desc' },
            include: { _count: { select: { findings: true } } },
        });
        return NextResponse.json(scans);
    } catch (error) {
        return NextResponse.json({ error: 'Failed to fetch scans' }, { status: 500 });
    }
}

export async function POST(req: Request) {
    try {
        const { target, resumeId } = await req.json();

        if (resumeId) {
            const existing = await prisma.scan.findUnique({ where: { id: resumeId } });
            if (!existing) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });

            // Start background resume
            runBackgroundScan(resumeId);
            return NextResponse.json(existing);
        }

        if (!target) {
            return NextResponse.json({ error: 'Target is required' }, { status: 400 });
        }

        const { ips, mappings, discoveryDetails } = await getTargetIps(target);

        if (ips.length === 0) {
            return NextResponse.json({ error: 'Could not resolve any IP addresses for the given target.' }, { status: 400 });
        }

        // Create scan record
        const scan = await prisma.scan.create({
            data: {
                target,
                status: 'PENDING',
                type: 'MANUAL',
                totalIps: ips.length,
                ipList: JSON.stringify(ips),
                currentIndex: 0,
            },
        });

        // Save DNS Discovery finding if we have domain discovery details
        if (discoveryDetails.length > 0) {
            const isDomain = !/^[0-9.]+$/.test(target.toLowerCase()) && !target.includes('/');
            if (isDomain) {
                // Categorize discovery details
                const dnsDetails = discoveryDetails.filter(d =>
                    d.includes('A Records') || d.includes('CNAME') || d.includes('NS') ||
                    d.includes('MX Record') || d.includes('Nameservers') || d.includes('Discovered Subdomain') ||
                    d.includes('Reverse DNS')
                );
                const securityDetails = discoveryDetails.filter(d =>
                    d.includes('SPF') || d.includes('DMARC') || d.includes('Email Security') ||
                    d.includes('SSL')
                );
                const tlsDetails = discoveryDetails.filter(d =>
                    d.includes('SSL Certificate') || d.includes('SSL SAN')
                );

                // Determine severity based on security findings
                let severity = 'INFO';
                if (discoveryDetails.some(d => d.includes('⚠️'))) severity = 'MEDIUM';
                if (discoveryDetails.some(d => d.includes('EXPIRED'))) severity = 'HIGH';

                // Create a consolidated forensics view
                const forensicsText = [
                    '=== DNS DISCOVERY ===',
                    ...dnsDetails,
                    '',
                    '=== EMAIL SECURITY ===',
                    ...securityDetails.filter(d => d.includes('SPF') || d.includes('DMARC') || d.includes('Email')),
                    '',
                    '=== TLS/SSL ANALYSIS ===',
                    ...tlsDetails,
                ].filter(line => line || line === '').join('\n');

                // Find vulnerabilities from security details
                const vulnerabilities = securityDetails.filter(d => d.includes('⚠️')).map(d => d.replace('⚠️ ', '')).join('; ');

                await prisma.finding.upsert({
                    where: { ip_port: { ip: '0.0.0.0', port: 0 } },
                    update: {
                        service: 'DNS Discovery',
                        severity: severity,
                        description: `Domain reconnaissance for ${target}. Discovered ${ips.length} IP addresses and ${discoveryDetails.filter(d => d.includes('Subdomain')).length} subdomains.`,
                        vulnerability: vulnerabilities || null,
                        forensics: forensicsText,
                        domains: target.toLowerCase(),
                        scans: { connect: { id: scan.id } },
                    },
                    create: {
                        ip: '0.0.0.0',
                        port: 0,
                        service: 'DNS Discovery',
                        severity: severity,
                        description: `Domain reconnaissance for ${target}. Discovered ${ips.length} IP addresses and ${discoveryDetails.filter(d => d.includes('Subdomain')).length} subdomains.`,
                        vulnerability: vulnerabilities || null,
                        forensics: forensicsText,
                        domains: target.toLowerCase(),
                        scans: { connect: { id: scan.id } },
                    },
                });
            }
        }

        // Start background scan with mapping context
        runBackgroundScan(scan.id, mappings);

        return NextResponse.json(scan);
    } catch (error) {
        console.error('API Scan POST error:', error);
        return NextResponse.json({ error: 'Invalid request' }, { status: 500 });
    }
}
