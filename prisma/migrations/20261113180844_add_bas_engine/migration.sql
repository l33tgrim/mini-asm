-- AlterTable
ALTER TABLE "Schedule" ADD COLUMN "lastRun" DATETIME;

-- CreateTable
CREATE TABLE "Engagement" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "mode" TEXT NOT NULL DEFAULT 'SAFE',
    "authorizedBy" TEXT,
    "authorizedAt" DATETIME,
    "revokedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "ScopeEntry" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "engagementId" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "verifyToken" TEXT,
    "verifyMethod" TEXT,
    "verifiedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScopeEntry_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "ScenarioRun" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "engagementId" TEXT NOT NULL,
    "scenarioId" TEXT NOT NULL,
    "scenarioName" TEXT NOT NULL,
    "playbookId" TEXT,
    "target" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'SAFE',
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "summary" TEXT,
    "startedAt" DATETIME,
    "completedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScenarioRun_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "ScenarioResult" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "runId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'INFO',
    "outcome" TEXT NOT NULL DEFAULT 'INFO',
    "attckTactic" TEXT,
    "attckTechnique" TEXT,
    "target" TEXT,
    "evidence" TEXT,
    "remediation" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScenarioResult_runId_fkey" FOREIGN KEY ("runId") REFERENCES "ScenarioRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "engagementId" TEXT,
    "action" TEXT NOT NULL,
    "target" TEXT,
    "detail" TEXT,
    "actor" TEXT NOT NULL DEFAULT 'system',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "Engagement" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "ScopeEntry_engagementId_value_key" ON "ScopeEntry"("engagementId", "value");
