-- Findings can now be TCP or UDP, so the same port number may appear twice on a host.
ALTER TABLE "Finding" ADD COLUMN "protocol" TEXT NOT NULL DEFAULT 'tcp';
DROP INDEX "Finding_ip_port_key";
CREATE UNIQUE INDEX "Finding_ip_port_protocol_key" ON "Finding"("ip", "port", "protocol");

-- Scans remember which ports they covered and whether UDP probes ran.
ALTER TABLE "Scan" ADD COLUMN "portSpec" TEXT;
ALTER TABLE "Scan" ADD COLUMN "udp" BOOLEAN NOT NULL DEFAULT true;
