<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * Gateway-ARP topology snapshot.
 *
 * Single source of truth for both the server-rendered Topology page
 * (pages/topology.php) and the AJAX refresh endpoint
 * (GET ?page=topology&format=json in public/index.php), so the map
 * always reflects the latest topology_links rows.
 */
final class Topology
{
    /**
     * @return array{nodes: array, edges: array, colors: array, stats: array, links: array, generated_at: string}
     */
    public static function snapshot(): array
    {
        $where = ' WHERE protocol = ' . Database::get()->quote('arp');
        $links = Database::q('SELECT * FROM topology_links' . $where . ' ORDER BY last_seen DESC LIMIT 500');

        // Build node set: local devices (known by IP) + remote devices (known by name)
        $nodes = [];
        $addNode = function (string $key, array $attrs) use (&$nodes): void {
            if (!isset($nodes[$key])) {
                $nodes[$key] = $attrs + ['id' => $key, 'degree' => 0];
            } else {
                foreach ($attrs as $k => $v) {
                    if (($nodes[$key][$k] ?? null) === null && $v !== null) {
                        $nodes[$key][$k] = $v;
                    }
                }
            }
            $nodes[$key]['degree']++;
        };

        // Map known IPs to their IPAM records so nodes can link into the app
        $known = [];
        foreach (Database::q('SELECT id, address, subnet_id, hostname FROM ip_addresses') as $r) {
            $known[$r['address']] = $r;
        }

        $edges = [];
        foreach ($links as $i => $l) {
            $a = $l['local_ip'];
            // Key remotes by management IP when known: a normalised neighbour then
            // merges with the same device's local node instead of rendering twice
            // (once per IP/name). The human-readable name stays as the label.
            $rname = trim((string)$l['remote_name']) !== '' ? $l['remote_name'] : ($l['remote_ip'] ?? 'unknown');
            $b = $l['remote_ip'] ?? $rname;

            $addNode($a, [
                'label'     => $l['local_name'] ?: $l['local_ip'],
                'ip'        => $l['local_ip'],
                'managed'   => isset($known[$l['local_ip']]),
                'ip_id'     => $known[$l['local_ip']]['id'] ?? null,
                'subnet_id' => $known[$l['local_ip']]['subnet_id'] ?? null,
                'descr'     => null,
            ]);
            $addNode($b, [
                'label'     => $rname,
                'ip'        => $l['remote_ip'],
                'managed'   => $l['remote_ip'] !== null && isset($known[$l['remote_ip']]),
                'ip_id'     => $l['remote_ip'] !== null ? ($known[$l['remote_ip']]['id'] ?? null) : null,
                'subnet_id' => $l['remote_ip'] !== null ? ($known[$l['remote_ip']]['subnet_id'] ?? null) : null,
                'descr'     => $l['remote_descr'],
            ]);

            $edges[] = [
                'source'   => $a,
                'target'   => $b,
                'protocol' => $l['protocol'],
                'sport'    => $l['local_port'],
                'tport'    => $l['remote_port'],
                'seen'     => $l['last_seen'],
            ];

            // Enrich the raw link row so the AJAX table re-render can link
            // managed local devices to their subnet page without a second query.
            $links[$i]['local_subnet_id'] = $known[$l['local_ip']]['subnet_id'] ?? null;
        }

        return [
            'nodes'  => array_values($nodes),
            'edges'  => $edges,
            'colors' => ['arp' => '#f59e0b'],
            'stats'  => [
                'nodes' => count($nodes),
                'edges' => count($edges),
                'arp'   => count($links),
            ],
            'links'  => $links,
            'generated_at' => date('c'),
        ];
    }
}
