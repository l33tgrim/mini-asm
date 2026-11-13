-- CreateTable
CREATE TABLE "CustomPlaybook" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "threat" TEXT,
    "attckTactics" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "PlaybookStep" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "playbookId" TEXT NOT NULL,
    "scenarioId" TEXT NOT NULL,
    "order" INTEGER NOT NULL DEFAULT 0,
    "params" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "PlaybookStep_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "CustomPlaybook" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
