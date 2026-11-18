-- Schedules remember the port settings of the scan they were made from.
ALTER TABLE "Schedule" ADD COLUMN "portSpec" TEXT;
ALTER TABLE "Schedule" ADD COLUMN "udp" BOOLEAN NOT NULL DEFAULT true;
