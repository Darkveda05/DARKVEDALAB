#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * DarkVeda IPAM — CLI discovery runner (cron-friendly).
 *
 *   php bin/discover.php --all            scan every active IPv4 subnet (/22 or smaller)
 *   php bin/discover.php --subnet=3       scan one subnet by id
 *
 * Cron example (every 30 minutes):
 *   0,30 * * * *  php /path/to/darkveda-ipam/bin/discover.php --all
 */

require dirname(__DIR__) . '/src/App.php';
require dirname(__DIR__) . '/src/Database.php';
require dirname(__DIR__) . '/src/IpTools.php';
require dirname(__DIR__) . '/src/Snmp.php';
require dirname(__DIR__) . '/src/Zabbix.php';
require dirname(__DIR__) . '/src/Discovery.php';

use DarkVeda\{Database, Discovery};

if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

$opts = getopt('', ['all', 'subnet:']);
$targets = [];

if (isset($opts['subnet'])) {
    $targets[] = (int)$opts['subnet'];
} elseif (isset($opts['all'])) {
    foreach (Database::q(
        "SELECT id FROM subnets WHERE ip_version = 4 AND prefix_len >= 22 AND status = 'active' ORDER BY id"
    ) as $r) {
        $targets[] = (int)$r['id'];
    }
} else {
    exit("Usage: php bin/discover.php --all | --subnet=<id>\n");
}

if (!$targets) {
    exit("No eligible subnets (IPv4, /22 or smaller, status active).\n");
}

foreach ($targets as $id) {
    try {
        $r = Discovery::scanSubnet($id, null);
        printf(
            "subnet #%d: scanned %d, alive %d, new %d, changed %d, silent-known %d, macs %d, hostnames %d, snmp %d, links %d (lldp/cdp %d, fdb %d, arp %d)\n",
            $id, $r['scanned'], $r['alive'], $r['new'], $r['changed'], $r['unreachable_known'],
            $r['macs_found'], $r['names_found'], $r['snmp_found'], $r['links_found'],
            $r['lldp_cdp_links'] ?? $r['links_found'], $r['fdb_links'] ?? 0, $r['arp_links'] ?? 0
        );
        if ($r['alive'] > 0 && $r['macs_found'] === 0) {
            fwrite(STDERR, "  hint: no MACs visible — scanner is not on this L2 segment (bridged/NAT?)\n");
        }
    } catch (Throwable $e) {
        fwrite(STDERR, "subnet #{$id}: " . $e->getMessage() . "\n");
    }
}
