/*
  Warnings:

  - You are about to drop the column `scanId` on the `Finding` table. All the data in the column will be lost.
  - Added the required column `updatedAt` to the `Finding` table without a default value. This is not possible if the table is not empty.

*/
-- CreateTable
CREATE TABLE "_FindingToScan" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL,
    CONSTRAINT "_FindingToScan_A_fkey" FOREIGN KEY ("A") REFERENCES "Finding" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "_FindingToScan_B_fkey" FOREIGN KEY ("B") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "ip" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "service" TEXT,
    "severity" TEXT NOT NULL,
    "description" TEXT,
    "vulnerability" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_Finding" ("createdAt", "description", "id", "ip", "port", "service", "severity", "vulnerability") SELECT "createdAt", "description", "id", "ip", "port", "service", "severity", "vulnerability" FROM "Finding";
DROP TABLE "Finding";
ALTER TABLE "new_Finding" RENAME TO "Finding";
CREATE UNIQUE INDEX "Finding_ip_port_key" ON "Finding"("ip", "port");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE UNIQUE INDEX "_FindingToScan_AB_unique" ON "_FindingToScan"("A", "B");

-- CreateIndex
CREATE INDEX "_FindingToScan_B_index" ON "_FindingToScan"("B");
