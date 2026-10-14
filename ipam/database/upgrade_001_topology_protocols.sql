-- DarkVeda IPAM upgrade 001 — topology: FDB + ARP link protocols.
-- Applied automatically at container start (see docker/entrypoint.sh).
-- Safe to run twice: the second run fails harmlessly and is skipped.

-- 1. Allow switch-forwarding-table (fdb) and gateway-ARP (arp) edges.
ALTER TABLE topology_links
  MODIFY protocol ENUM('lldp','cdp','fdb','arp') NOT NULL;

-- 2. Scope link identity per protocol: the same device pair observed via
--    LLDP and via FDB are two distinct observations, not one row.
ALTER TABLE topology_links
  DROP INDEX uq_link,
  ADD UNIQUE KEY uq_link (protocol, local_ip, local_port, remote_name, remote_port);
