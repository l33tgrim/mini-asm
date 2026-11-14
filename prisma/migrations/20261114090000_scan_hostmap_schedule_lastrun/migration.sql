-- AlterTable
ALTER TABLE "Scan" ADD COLUMN "hostMap" TEXT;

-- AlterTable
ALTER TABLE "Schedule" ADD COLUMN "lastRunAt" DATETIME;
