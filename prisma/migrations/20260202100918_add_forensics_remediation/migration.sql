-- AlterTable
ALTER TABLE "Finding" ADD COLUMN "confidence" INTEGER DEFAULT 100;
ALTER TABLE "Finding" ADD COLUMN "discoveryMethod" TEXT DEFAULT 'ACTIVE_PROBE';
ALTER TABLE "Finding" ADD COLUMN "forensics" TEXT;
ALTER TABLE "Finding" ADD COLUMN "remediation" TEXT;
ALTER TABLE "Finding" ADD COLUMN "upstreamVersion" TEXT;
