import tls from 'tls';
import type { Scenario, ScenarioResult } from '../types';
import { ensureServices } from './_shared';
import { acquire } from '@/lib/safety/ratelimit';

interface TlsInfo {
    issuer: string;
    validTo: string;
    protocol: string | null;
    daysLeft: number;
    selfSigned: boolean;
    error?: string;
}

function inspectTls(host: string, port: number): Promise<TlsInfo> {
    return new Promise(async (resolve) => {
        await acquire(host);
        const socket = tls.connect(
            { host, port, servername: host, timeout: 6000, rejectUnauthorized: false },
            () => {
                try {
                    const cert = socket.getPeerCertificate();
                    const validTo = cert?.valid_to || 'Unknown';
                    const daysLeft = validTo !== 'Unknown' ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000) : 0;
                    resolve({
                        issuer: cert?.issuer?.O || cert?.issuer?.CN || 'Unknown',
                        validTo,
                        protocol: socket.getProtocol(),
                        daysLeft,
                        selfSigned: !!cert && cert.issuer?.CN === cert.subject?.CN,
                    });
                } catch (e) {
                    resolve({ issuer: 'Unknown', validTo: 'Unknown', protocol: null, daysLeft: 0, selfSigned: false, error: (e as Error).message });
                }
                socket.end();
            }
        );
        socket.on('error', (e) => resolve({ issuer: 'Unknown', validTo: 'Unknown', protocol: null, daysLeft: 0, selfSigned: false, error: e.message }));
        socket.on('timeout', () => {
            socket.destroy();
            resolve({ issuer: 'Unknown', validTo: 'Unknown', protocol: null, daysLeft: 0, selfSigned: false, error: 'timeout' });
        });
    });
}

export const tlsPosture: Scenario = {
    id: 'tls-posture',
    name: 'TLS / Certificate Posture',
    description: 'Check certificate expiry, weak TLS versions, and self-signed certificates on TLS services.',
    category: 'POSTURE',
    maxSeverity: 'HIGH',
    attckTactic: 'Collection',
    attckTechnique: 'T1040 Network Sniffing',
    requiresActive: false,
    intrusive: false,
    tags: ['tls', 'crypto', 'certificates'],
    async run(ctx) {
        const results: ScenarioResult[] = [];
        const services = await ensureServices(ctx);
        const tlsPorts = services.filter((s) => [443, 8443, 993, 995, 465, 636, 5986].includes(s.port));

        if (tlsPorts.length === 0) {
            results.push({ title: 'No TLS services to assess', severity: 'INFO', outcome: 'INFO', target: ctx.target, evidence: 'No TLS-bearing ports found.' });
            return results;
        }

        for (const s of tlsPorts) {
            const host = s.domains?.split(',')[0] || s.ip;
            const info = await inspectTls(host, s.port);
            if (info.error) continue;

            if (info.daysLeft < 0) {
                results.push({ title: `Expired certificate on ${host}:${s.port}`, severity: 'HIGH', outcome: 'VULNERABLE', target: `${host}:${s.port}`, evidence: `Certificate from ${info.issuer} expired on ${info.validTo}.`, remediation: 'Renew the certificate immediately.' });
            } else if (info.daysLeft < 30) {
                results.push({ title: `Certificate expiring soon on ${host}:${s.port}`, severity: 'MEDIUM', outcome: 'VULNERABLE', target: `${host}:${s.port}`, evidence: `Certificate expires in ${info.daysLeft} days (${info.validTo}).`, remediation: 'Renew and automate certificate rotation.' });
            }

            if (info.protocol && (info.protocol.includes('TLSv1.0') || info.protocol.includes('TLSv1.1'))) {
                results.push({ title: `Weak TLS version on ${host}:${s.port}`, severity: 'HIGH', outcome: 'VULNERABLE', target: `${host}:${s.port}`, attckTechnique: 'T1040 Network Sniffing', evidence: `Negotiated ${info.protocol}, which is deprecated.`, remediation: 'Disable TLS 1.0/1.1; require TLS 1.2+.' });
            }

            if (info.selfSigned) {
                results.push({ title: `Self-signed certificate on ${host}:${s.port}`, severity: 'MEDIUM', outcome: 'VULNERABLE', target: `${host}:${s.port}`, evidence: `Issuer equals subject (${info.issuer}).`, remediation: 'Use a certificate from a trusted CA.' });
            }
        }

        if (results.length === 0) {
            results.push({ title: 'TLS posture looks healthy', severity: 'INFO', outcome: 'SECURE', target: ctx.target, evidence: 'No expired, weak, or self-signed certificates found.' });
        }
        return results;
    },
};
