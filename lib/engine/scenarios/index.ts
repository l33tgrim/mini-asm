import type { Scenario } from '../types';
import { reconExposure } from './recon-exposure';
import { exposedServices } from './exposed-services';
import { tlsPosture } from './tls-posture';
import { securityHeaders } from './security-headers';
import { emailPosture } from './email-posture';
import { cveEnrichment } from './cve-enrichment';
import { wafDetectBypass } from './waf-detect-bypass';
import { proofOfReach } from './proof-of-reach';
import { proofOfCommand } from './proof-of-command';
import { proofOfData } from './proof-of-data';
import { customHttpChecks } from './custom-http-checks';

/**
 * The scenario catalog. To add a scenario, create a file in this directory that
 * exports a `Scenario`, import it here, and add it to this array. See
 * docs/SCENARIOS.md.
 */
export const ALL_SCENARIOS: Scenario[] = [
    reconExposure,
    exposedServices,
    tlsPosture,
    securityHeaders,
    emailPosture,
    cveEnrichment,
    wafDetectBypass,
    proofOfReach,
    proofOfCommand,
    proofOfData,
    customHttpChecks,
];
