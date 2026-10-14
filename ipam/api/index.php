<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/App.php';
require dirname(__DIR__) . '/src/Database.php';
require dirname(__DIR__) . '/src/Auth.php';
require dirname(__DIR__) . '/src/Audit.php';
require dirname(__DIR__) . '/src/IpTools.php';
require dirname(__DIR__) . '/src/Snmp.php';
require dirname(__DIR__) . '/src/Zabbix.php';

use DarkVeda\{App, Auth, Audit, Database, IpTools, Snmp, Zabbix};

header('Content-Type: application/json; charset=utf-8');

function json_out(mixed $data, int $code = 200): never
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function json_error(string $message, int $code = 400): never
{
    json_out(['error' => $message], $code);
}

// Bootstrap without web session
App::config();
date_default_timezone_set(App::config()['app']['timezone']);

$apiUser = Auth::apiUser();
if (!$apiUser) {
    json_error('Missing or invalid bearer token.', 401);
}
// Make Audit::log attribute actions to the token owner
$_SESSION['user'] = ['id' => (int)$apiUser['id']];

$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$path   = preg_replace('#^/api/v1#', '', $path) ?: '/';
$body   = json_decode(file_get_contents('php://input') ?: '[]', true) ?? [];

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------

// GET /subnets
if ($method === 'GET' && $path === '/subnets') {
    json_out(Database::q(
        'SELECT s.id, s.cidr, s.name, s.ip_version, s.prefix_len, s.status, s.description,
                v.vid AS vlan, st.name AS site,
                (SELECT COUNT(*) FROM ip_addresses i WHERE i.subnet_id = s.id) AS assigned
         FROM subnets s
         LEFT JOIN vlans v ON v.id = s.vlan_id
         LEFT JOIN sites st ON st.id = s.site_id
         ORDER BY s.ip_version, s.network_bin'
    ));
}

// POST /subnets
if ($method === 'POST' && $path === '/subnets') {
    $parsed = IpTools::parseCidr((string)($body['cidr'] ?? ''));
    if (!$parsed) {
        json_error('Invalid or missing "cidr".');
    }
    try {
        Database::exec(
            'INSERT INTO subnets (cidr, network_bin, prefix_len, ip_version, name, vlan_id, site_id, status, description)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            [
                $parsed['network'] . '/' . $parsed['prefix'],
                $parsed['network_bin'],
                $parsed['prefix'],
                $parsed['version'],
                $body['name'] ?? null,
                $body['vlan_id'] ?? null,
                $body['site_id'] ?? null,
                $body['status'] ?? 'active',
                $body['description'] ?? null,
            ]
        );
    } catch (PDOException $e) {
        json_error(str_contains($e->getMessage(), 'Duplicate') ? 'Subnet already exists in this VRF.' : 'Database error.', 409);
    }
    $id = Database::lastId();
    Audit::log('create', 'subnet', (string)$id, $parsed['network'] . '/' . $parsed['prefix'] . ' (api)');
    json_out(['id' => $id, 'cidr' => $parsed['network'] . '/' . $parsed['prefix']], 201);
}

// /subnets/{id}/ips
if (preg_match('#^/subnets/(\d+)/ips$#', $path, $m)) {
    $subnetId = (int)$m[1];
    $subnet = Database::one('SELECT * FROM subnets WHERE id = ?', [$subnetId]);
    if (!$subnet) {
        json_error('Subnet not found.', 404);
    }

    if ($method === 'GET') {
        json_out(Database::q(
            'SELECT id, address, status, hostname, mac_address, serial_number, device_type_id, os, software_version, description, updated_at
             FROM ip_addresses WHERE subnet_id = ? ORDER BY address_bin',
            [$subnetId]
        ));
    }

    if ($method === 'POST') {
        $address = (string)($body['address'] ?? '');
        if ($address === '' || $address === 'auto') {
            // auto-assign next free (IPv4 only)
            $used = array_column(
                Database::q('SELECT address_bin FROM ip_addresses WHERE subnet_id = ?', [$subnetId]),
                'address_bin'
            );
            $address = IpTools::firstFreeV4($subnet['network_bin'], (int)$subnet['prefix_len'], $used) ?? '';
            if ($address === '') {
                json_error('No free address available (auto-assign is IPv4 only).', 409);
            }
        }
        $ip = IpTools::parseIp($address);
        if (!$ip || !IpTools::inSubnet($ip['bin'], $subnet['network_bin'], (int)$subnet['prefix_len'])) {
            json_error('Address is invalid or outside the subnet.');
        }
        try {
            Database::exec(
                'INSERT INTO ip_addresses (subnet_id, address, address_bin, status, hostname, mac_address, serial_number, device_type_id, os, software_version, description)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                [
                    $subnetId, $ip['address'], $ip['bin'],
                    $body['status'] ?? 'active',
                    $body['hostname'] ?? null,
                    $body['mac_address'] ?? null,
                    $body['serial_number'] ?? null,
                    (int)($body['device_type_id'] ?? 0) ?: null,
                    $body['os'] ?? null,
                    $body['software_version'] ?? null,
                    $body['description'] ?? null,
                ]
            );
        } catch (PDOException) {
            json_error('IP already assigned in this subnet.', 409);
        }
        $id = Database::lastId();
        Audit::log('create', 'ip_address', (string)$id, $ip['address'] . ' (api)');
        json_out(['id' => $id, 'address' => $ip['address']], 201);
    }
}

// GET /ips?search=
if ($method === 'GET' && $path === '/ips') {
    $search = trim((string)($_GET['search'] ?? ''));
    $like = '%' . $search . '%';
    json_out(Database::q(
        'SELECT i.id, i.address, i.status, i.hostname, i.mac_address, i.serial_number, i.os, i.software_version,
                TRIM(CONCAT(COALESCE(v2.name, ""), " ", dt2.model)) AS device_type, s.cidr AS subnet
         FROM ip_addresses i JOIN subnets s ON s.id = i.subnet_id
         LEFT JOIN device_types dt2 ON dt2.id = i.device_type_id
         LEFT JOIN vendors v2 ON v2.id = dt2.vendor_id
         WHERE i.address LIKE ? OR i.hostname LIKE ? OR i.serial_number LIKE ?
         ORDER BY i.address_bin LIMIT 100',
        [$like, $like, $like]
    ));
}

// DELETE /ips/{id}
if ($method === 'DELETE' && preg_match('#^/ips/(\d+)$#', $path, $m)) {
    $id = (int)$m[1];
    $row = Database::one('SELECT address FROM ip_addresses WHERE id = ?', [$id]);
    if (!$row) {
        json_error('IP not found.', 404);
    }
    Database::exec('DELETE FROM ip_addresses WHERE id = ?', [$id]);
    Audit::log('delete', 'ip_address', (string)$id, $row['address'] . ' (api)');
    json_out(['deleted' => $id]);
}

// GET /vlans
if ($method === 'GET' && $path === '/vlans') {
    json_out(Database::q(
        'SELECT v.id, v.vid, v.name, v.status, s.name AS site
         FROM vlans v LEFT JOIN sites s ON s.id = v.site_id ORDER BY v.vid'
    ));
}

// GET /device-types
if ($method === 'GET' && $path === '/device-types') {
    json_out(Database::q(
        'SELECT dt.id, dt.model, dt.u_height, v.name AS vendor
         FROM device_types dt
         LEFT JOIN vendors v ON v.id = dt.vendor_id
         ORDER BY v.name, dt.model'
    ));
}


// ---------------- automation endpoints ----------------

// POST /ips/upsert  {address, subnet_cidr?|subnet_id?, hostname?, mac_address?, serial_number?,
//                    os?, software_version?, status?, device_type_id?, description?}
if ($method === 'POST' && $path === '/ips/upsert') {
    $addr = IpTools::parseIp((string)($body['address'] ?? ''));
    if (!$addr) {
        json_error('A valid "address" is required.', 422);
    }

    // resolve subnet: explicit id, explicit cidr, or automatically by containment
    $subnet = null;
    if (!empty($body['subnet_id'])) {
        $subnet = Database::one('SELECT * FROM subnets WHERE id = ?', [(int)$body['subnet_id']]);
    } elseif (!empty($body['subnet_cidr'])) {
        $subnet = Database::one('SELECT * FROM subnets WHERE cidr = ?', [(string)$body['subnet_cidr']]);
    } else {
        foreach (Database::q('SELECT * FROM subnets WHERE ip_version = ?', [$addr['version']]) as $s) {
            if (IpTools::inSubnet($addr['bin'], $s['network_bin'], (int)$s['prefix_len'])) {
                $subnet = $s;
                break;
            }
        }
    }
    if (!$subnet) {
        json_error('No matching subnet — pass subnet_id or subnet_cidr, or create the subnet first.', 422);
    }
    if (!IpTools::inSubnet($addr['bin'], $subnet['network_bin'], (int)$subnet['prefix_len'])) {
        json_error('Address is not inside ' . $subnet['cidr'] . '.', 422);
    }

    $st = (string)($body['status'] ?? 'active');
    $status = in_array($st, ['active','reserved','dhcp','gateway','deprecated'], true) ? $st : 'active';
    $mac = isset($body['mac_address']) ? Snmp::normaliseMac((string)$body['mac_address']) : null;

    $existing = Database::one(
        'SELECT id FROM ip_addresses WHERE subnet_id = ? AND address_bin = ?',
        [(int)$subnet['id'], $addr['bin']]
    );

    $fields = [
        'status'           => $status,
        'hostname'         => $body['hostname'] ?? null,
        'mac_address'      => $mac,
        'serial_number'    => $body['serial_number'] ?? null,
        'os'               => $body['os'] ?? null,
        'software_version' => $body['software_version'] ?? null,
        'device_type_id'   => isset($body['device_type_id']) ? ((int)$body['device_type_id'] ?: null) : null,
        'description'      => $body['description'] ?? null,
    ];

    if ($existing) {
        // COALESCE semantics: only overwrite when a value was supplied
        $set = [];
        $args = [];
        foreach ($fields as $col => $val) {
            if ($val !== null || $col === 'status') {
                $set[] = "$col = ?";
                $args[] = $val;
            }
        }
        $set[] = 'last_seen = NOW()';
        $args[] = (int)$existing['id'];
        Database::exec('UPDATE ip_addresses SET ' . implode(', ', $set) . ' WHERE id = ?', $args);
        json_out(['id' => (int)$existing['id'], 'address' => $addr['address'], 'created' => false]);
    }

    Database::exec(
        'INSERT INTO ip_addresses
            (subnet_id, address, address_bin, status, hostname, mac_address, serial_number,
             os, software_version, device_type_id, description, last_seen)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,NOW())',
        [
            (int)$subnet['id'], $addr['address'], $addr['bin'], $status,
            $fields['hostname'], $fields['mac_address'], $fields['serial_number'],
            $fields['os'], $fields['software_version'], $fields['device_type_id'], $fields['description'],
        ]
    );
    json_out(['id' => (int)Database::lastId(), 'address' => $addr['address'], 'created' => true], 201);
}

// POST /monitoring  — single object or {"items":[...]}
// {address, state: online|offline|unknown, cpu_pct?, memory_pct?, host_name?, problem_count?, uptime_seconds?, source?}
if ($method === 'POST' && $path === '/monitoring') {
    $items = isset($body['items']) && is_array($body['items']) ? $body['items'] : [$body];
    $ok = 0;
    $errors = [];
    foreach ($items as $i => $it) {
        $addr = trim((string)($it['address'] ?? ''));
        if (!filter_var($addr, FILTER_VALIDATE_IP)) {
            $errors[] = ['index' => $i, 'error' => 'invalid address'];
            continue;
        }
        Zabbix::store(
            $addr,
            (string)($it['state'] ?? 'unknown'),
            isset($it['cpu_pct']) && is_numeric($it['cpu_pct']) ? (float)$it['cpu_pct'] : null,
            isset($it['memory_pct']) && is_numeric($it['memory_pct']) ? (float)$it['memory_pct'] : null,
            isset($it['host_name']) ? (string)$it['host_name'] : null,
            (int)($it['problem_count'] ?? 0),
            isset($it['uptime_seconds']) ? (int)$it['uptime_seconds'] : null,
            (string)($it['source'] ?? 'api')
        );
        $ok++;
    }
    json_out(['stored' => $ok, 'errors' => $errors], $errors && !$ok ? 422 : 200);
}

// GET /monitoring
if ($method === 'GET' && $path === '/monitoring') {
    json_out(Database::q(
        'SELECT address, source, state, cpu_pct, memory_pct, uptime_seconds, host_name, problem_count, checked_at
         FROM monitoring_status ORDER BY address'
    ));
}

// GET /topology
if ($method === 'GET' && $path === '/topology') {
    json_out(Database::q(
        'SELECT protocol, local_ip, local_name, local_port, remote_name, remote_port, remote_ip, remote_descr, last_seen
         FROM topology_links ORDER BY local_ip, local_port LIMIT 1000'
    ));
}

// POST /topology  — {"links":[{protocol,local_ip,local_name?,local_port,remote_name,remote_port,remote_ip?,remote_descr?}]}
if ($method === 'POST' && $path === '/topology') {
    $links = isset($body['links']) && is_array($body['links']) ? $body['links'] : [$body];
    $ok = 0;
    foreach ($links as $l) {
        $proto = ($l['protocol'] ?? 'lldp') === 'cdp' ? 'cdp' : 'lldp';
        $localIp = trim((string)($l['local_ip'] ?? ''));
        if (!filter_var($localIp, FILTER_VALIDATE_IP)) {
            continue;
        }
        Database::exec(
            'INSERT INTO topology_links
                (protocol, local_ip, local_name, local_port, remote_name, remote_port, remote_ip, remote_descr)
             VALUES (?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE last_seen = NOW(), local_name = VALUES(local_name),
                remote_ip = COALESCE(VALUES(remote_ip), remote_ip),
                remote_descr = COALESCE(VALUES(remote_descr), remote_descr)',
            [
                $proto, $localIp,
                $l['local_name'] ?? null,
                (string)($l['local_port'] ?? ''),
                (string)($l['remote_name'] ?? ''),
                (string)($l['remote_port'] ?? ''),
                $l['remote_ip'] ?? null,
                $l['remote_descr'] ?? null,
            ]
        );
        $ok++;
    }
    json_out(['stored' => $ok]);
}

// GET /racks
if ($method === 'GET' && $path === '/racks') {
    $racks = Database::q(
        'SELECT r.id, r.name, r.u_height, s.name AS site FROM racks r
         LEFT JOIN sites s ON s.id = r.site_id ORDER BY r.name'
    );
    foreach ($racks as &$r) {
        $r['devices'] = Database::q(
            'SELECT i.address, i.hostname, i.rack_position, i.rack_face,
                    TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS device_type
             FROM ip_addresses i
             LEFT JOIN device_types dt ON dt.id = i.device_type_id
             LEFT JOIN vendors v ON v.id = dt.vendor_id
             WHERE i.rack_id = ? AND i.rack_position IS NOT NULL
             ORDER BY i.rack_position DESC',
            [(int)$r['id']]
        );
    }
    unset($r);
    json_out($racks);
}

json_error('Route not found. See /api/index.php header for available endpoints.', 404);
