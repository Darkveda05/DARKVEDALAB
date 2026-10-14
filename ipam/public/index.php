<?php
declare(strict_types=1);

/**
 * DarkVeda IPAM — front controller
 */

require dirname(__DIR__) . '/src/App.php';
require dirname(__DIR__) . '/src/Database.php';
require dirname(__DIR__) . '/src/Auth.php';
require dirname(__DIR__) . '/src/Audit.php';
require dirname(__DIR__) . '/src/IpTools.php';
require dirname(__DIR__) . '/src/Snmp.php';
require dirname(__DIR__) . '/src/Zabbix.php';
require dirname(__DIR__) . '/src/Discovery.php';
require dirname(__DIR__) . '/src/Settings.php';
require dirname(__DIR__) . '/src/Uploads.php';
require dirname(__DIR__) . '/src/Backup.php';
require dirname(__DIR__) . '/src/ImageSearch.php';
require dirname(__DIR__) . '/src/Topology.php';

use DarkVeda\{App, Auth, Audit, Database, IpTools, Discovery, Snmp, Zabbix, Settings, Uploads, Backup, ImageSearch, Topology};

App::boot();

$page   = $_GET['page']   ?? 'dashboard';
$action = $_POST['action'] ?? null;

// ------------------------------------------------------------------
// POST actions
// ------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== null) {
    if ($action !== 'login') {
        Auth::requirePermission();
        Auth::verifyCsrf();
    }

    switch ($action) {

        case 'login':
            if (Auth::attempt(trim($_POST['username'] ?? ''), $_POST['password'] ?? '')) {
                App::redirect('/?page=dashboard');
            }
            App::flash('danger', 'Invalid username or password.');
            App::redirect('/?page=login');

        case 'logout':
            Auth::logout();
            App::redirect('/?page=login');

        // ---------------- Subnets ----------------
        case 'subnet_create':
            Auth::requirePermission('ipam.manage');
            $parsed = IpTools::parseCidr($_POST['cidr'] ?? '');
            if (!$parsed) {
                App::flash('danger', 'Invalid CIDR notation.');
                App::redirect('/?page=subnets');
            }
            try {
                Database::exec(
                    'INSERT INTO subnets (cidr, network_bin, prefix_len, ip_version, name, vlan_id, site_id, gateway, status, description)
                     VALUES (?,?,?,?,?,?,?,?,?,?)',
                    [
                        $parsed['network'] . '/' . $parsed['prefix'],
                        $parsed['network_bin'],
                        $parsed['prefix'],
                        $parsed['version'],
                        trim($_POST['name'] ?? '') ?: null,
                        (int)($_POST['vlan_id'] ?? 0) ?: null,
                        (int)($_POST['site_id'] ?? 0) ?: null,
                        trim($_POST['gateway'] ?? '') ?: null,
                        $_POST['status'] ?? 'active',
                        trim($_POST['description'] ?? '') ?: null,
                    ]
                );
                Audit::log('create', 'subnet', (string)Database::lastId(), $parsed['network'] . '/' . $parsed['prefix']);
                App::flash('success', 'Subnet created.');
            } catch (PDOException $e) {
                App::flash('danger', str_contains($e->getMessage(), 'Duplicate')
                    ? 'That subnet already exists.' : 'Database error creating subnet.');
            }
            App::redirect('/?page=subnets');

        case 'subnet_delete':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('DELETE FROM subnets WHERE id = ?', [$id]);
            Audit::log('delete', 'subnet', (string)$id);
            App::flash('success', 'Subnet deleted (and its IP records).');
            App::redirect('/?page=subnets');

        // ---------------- IP addresses ----------------
        case 'ip_create':
            Auth::requirePermission('ipam.manage');
            $subnetId = (int)($_POST['subnet_id'] ?? 0);
            $subnet = Database::one('SELECT * FROM subnets WHERE id = ?', [$subnetId]);
            $ip = IpTools::parseIp($_POST['address'] ?? '');
            if (!$subnet || !$ip) {
                App::flash('danger', 'Invalid subnet or IP address.');
                App::redirect('/?page=subnets');
            }
            if (!IpTools::inSubnet($ip['bin'], $subnet['network_bin'], (int)$subnet['prefix_len'])) {
                App::flash('danger', $ip['address'] . ' is not inside ' . $subnet['cidr'] . '.');
                App::redirect('/?page=subnet_view&id=' . $subnetId);
            }
            try {
                Database::exec(
                    'INSERT INTO ip_addresses (subnet_id, address, address_bin, status, hostname, device_type_id, mac_address, serial_number, os, software_version, description)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                    [
                        $subnetId,
                        $ip['address'],
                        $ip['bin'],
                        $_POST['status'] ?? 'active',
                        trim($_POST['hostname'] ?? '') ?: null,
                        (int)($_POST['device_type_id'] ?? 0) ?: null,
                        trim($_POST['mac_address'] ?? '') ?: null,
                        trim($_POST['serial_number'] ?? '') ?: null,
                        trim($_POST['os'] ?? '') ?: null,
                        trim($_POST['software_version'] ?? '') ?: null,
                        trim($_POST['description'] ?? '') ?: null,
                    ]
                );
                Audit::log('create', 'ip_address', (string)Database::lastId(), $ip['address']);
                App::flash('success', 'IP ' . $ip['address'] . ' assigned.');
            } catch (PDOException $e) {
                App::flash('danger', str_contains($e->getMessage(), 'Duplicate')
                    ? 'That IP is already assigned in this subnet.' : 'Database error assigning IP.');
            }
            App::redirect('/?page=subnet_view&id=' . $subnetId);

        case 'ip_delete':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            $row = Database::one('SELECT subnet_id, address FROM ip_addresses WHERE id = ?', [$id]);
            Database::exec('DELETE FROM ip_addresses WHERE id = ?', [$id]);
            Audit::log('delete', 'ip_address', (string)$id, $row['address'] ?? null);
            App::flash('success', 'IP released.');
            App::redirect('/?page=subnet_view&id=' . (int)($row['subnet_id'] ?? 0));

        // ---------------- VLANs ----------------
        case 'vlan_create':
            Auth::requirePermission('ipam.manage');
            $vid = (int)($_POST['vid'] ?? 0);
            if ($vid < 1 || $vid > 4094) {
                App::flash('danger', 'VLAN ID must be 1–4094.');
                App::redirect('/?page=vlans');
            }
            try {
                Database::exec(
                    'INSERT INTO vlans (site_id, vid, name, description, status) VALUES (?,?,?,?,?)',
                    [
                        (int)($_POST['site_id'] ?? 0) ?: null,
                        $vid,
                        trim($_POST['name'] ?? ''),
                        trim($_POST['description'] ?? '') ?: null,
                        $_POST['status'] ?? 'active',
                    ]
                );
                Audit::log('create', 'vlan', (string)Database::lastId(), 'VLAN ' . $vid);
                App::flash('success', 'VLAN created.');
            } catch (PDOException) {
                App::flash('danger', 'VLAN ID already exists at that site.');
            }
            App::redirect('/?page=vlans');

        case 'vlan_delete':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('DELETE FROM vlans WHERE id = ?', [$id]);
            Audit::log('delete', 'vlan', (string)$id);
            App::flash('success', 'VLAN deleted.');
            App::redirect('/?page=vlans');

        // ---------------- Users ----------------
        case 'user_create':
            Auth::requirePermission('users.manage');
            $password = $_POST['password'] ?? '';
            if (strlen($password) < 10) {
                App::flash('danger', 'Password must be at least 10 characters.');
                App::redirect('/?page=users');
            }
            try {
                Database::exec(
                    'INSERT INTO users (username, email, password_hash, full_name, role_id) VALUES (?,?,?,?,?)',
                    [
                        trim($_POST['username'] ?? ''),
                        trim($_POST['email'] ?? ''),
                        password_hash($password, PASSWORD_BCRYPT, ['cost' => App::config()['security']['bcrypt_cost']]),
                        trim($_POST['full_name'] ?? '') ?: null,
                        (int)($_POST['role_id'] ?? 3),
                    ]
                );
                Audit::log('create', 'user', (string)Database::lastId(), trim($_POST['username'] ?? ''));
                App::flash('success', 'User created.');
            } catch (PDOException) {
                App::flash('danger', 'Username or email already taken.');
            }
            App::redirect('/?page=users');

        case 'user_toggle':
            Auth::requirePermission('users.manage');
            $id = (int)($_POST['id'] ?? 0);
            if ($id === Auth::id()) {
                App::flash('danger', 'You cannot deactivate your own account.');
            } else {
                Database::exec('UPDATE users SET is_active = 1 - is_active WHERE id = ?', [$id]);
                Audit::log('update', 'user', (string)$id, 'toggled active flag');
                App::flash('success', 'User status updated.');
            }
            App::redirect('/?page=users');


        case 'dtype_update':
            Auth::requirePermission('devices.manage');
            $id = (int)($_POST['id'] ?? 0);
            $model = trim($_POST['model'] ?? '');
            if ($model === '') {
                App::flash('danger', 'Model name is required.');
                App::redirect('/?page=devices');
            }
            $vendorId = (int)($_POST['vendor_id'] ?? 0) ?: null;
            $vendorNew = trim($_POST['vendor_new'] ?? '');
            if ($vendorNew !== '') {
                $existing = Database::one('SELECT id FROM vendors WHERE name = ?', [$vendorNew]);
                if ($existing) {
                    $vendorId = (int)$existing['id'];
                } else {
                    Database::exec('INSERT INTO vendors (name) VALUES (?)', [$vendorNew]);
                    $vendorId = (int)Database::lastId();
                }
            }
            Database::exec(
                'UPDATE device_types SET vendor_id = ?, model = ?, u_height = ? WHERE id = ?',
                [$vendorId, $model, max(0, (int)($_POST['u_height'] ?? 1)), $id]
            );
            Audit::log('update', 'device_type', (string)$id, $model);
            App::flash('success', 'Device type updated.');
            App::redirect('/?page=devices');

        // ---------------- Sites ----------------
        case 'site_create':
            Auth::requirePermission('ipam.manage');
            $name = trim($_POST['name'] ?? '');
            if ($name === '') {
                App::flash('danger', 'Site name is required.');
                App::redirect('/?page=sites');
            }
            $slug = trim($_POST['slug'] ?? '');
            $slug = $slug !== '' ? $slug : strtolower(preg_replace('/[^a-z0-9]+/i', '-', $name));
            $slug = trim(preg_replace('/-+/', '-', $slug), '-');
            try {
                Database::exec(
                    'INSERT INTO sites (name, slug, address, description) VALUES (?,?,?,?)',
                    [$name, $slug, trim($_POST['address'] ?? '') ?: null, trim($_POST['description'] ?? '') ?: null]
                );
                Audit::log('create', 'site', (string)Database::lastId(), $name);
                App::flash('success', 'Site created.');
            } catch (PDOException) {
                App::flash('danger', 'A site with that name or slug already exists.');
            }
            App::redirect('/?page=sites');

        case 'site_delete':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            $inUse = Database::one(
                'SELECT (SELECT COUNT(*) FROM subnets WHERE site_id = ?) +
                        (SELECT COUNT(*) FROM devices WHERE site_id = ?) +
                        (SELECT COUNT(*) FROM vlans   WHERE site_id = ?) AS c',
                [$id, $id, $id]
            );
            if ((int)$inUse['c'] > 0) {
                App::flash('danger', 'Site is still referenced by subnets, VLANs or devices.');
            } else {
                Database::exec('DELETE FROM sites WHERE id = ?', [$id]);
                Audit::log('delete', 'site', (string)$id);
                App::flash('success', 'Site deleted.');
            }
            App::redirect('/?page=sites');

        // ---------------- Device types ----------------
        case 'dtype_create':
            Auth::requirePermission('devices.manage');
            $model = trim($_POST['model'] ?? '');
            if ($model === '') {
                App::flash('danger', 'Model name is required.');
                App::redirect('/?page=devices');
            }
            $vendorId = (int)($_POST['vendor_id'] ?? 0) ?: null;
            $vendorNew = trim($_POST['vendor_new'] ?? '');
            if ($vendorNew !== '') {
                $existing = Database::one('SELECT id FROM vendors WHERE name = ?', [$vendorNew]);
                if ($existing) {
                    $vendorId = (int)$existing['id'];
                } else {
                    Database::exec('INSERT INTO vendors (name) VALUES (?)', [$vendorNew]);
                    $vendorId = (int)Database::lastId();
                }
            }
            Database::exec(
                'INSERT INTO device_types (vendor_id, model, u_height) VALUES (?,?,?)',
                [$vendorId, $model, max(0, (int)($_POST['u_height'] ?? 1))]
            );
            Audit::log('create', 'device_type', (string)Database::lastId(), $model);
            App::flash('success', 'Device type added.');
            App::redirect('/?page=devices');

        case 'dtype_delete':
            Auth::requirePermission('devices.manage');
            $id = (int)($_POST['id'] ?? 0);
            $inUse = Database::one(
                'SELECT (SELECT COUNT(*) FROM devices WHERE device_type_id = ?) +
                        (SELECT COUNT(*) FROM ip_addresses WHERE device_type_id = ?) AS c',
                [$id, $id]
            );
            if ((int)$inUse['c'] > 0) {
                App::flash('danger', 'Device type is still assigned to IP addresses.');
            } else {
                Database::exec('DELETE FROM device_types WHERE id = ?', [$id]);
                Audit::log('delete', 'device_type', (string)$id);
                App::flash('success', 'Device type deleted.');
            }
            App::redirect('/?page=devices');


        case 'ip_update':
            Auth::requirePermission('ipam.manage');
            $id  = (int)($_POST['id'] ?? 0);
            $rec = Database::one('SELECT * FROM ip_addresses WHERE id = ?', [$id]);
            if (!$rec) {
                App::flash('danger', 'IP record not found.');
                App::redirect('/?page=subnets');
            }
            $mac = strtolower(trim($_POST['mac_address'] ?? ''));
            if ($mac !== '' && !preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $mac)) {
                App::flash('danger', 'MAC must look like aa:bb:cc:dd:ee:ff.');
                App::redirect('/?page=subnet_view&id=' . (int)$rec['subnet_id']);
            }
            Database::exec(
                'UPDATE ip_addresses
                 SET status = ?, hostname = ?, device_type_id = ?, mac_address = ?, serial_number = ?, os = ?, software_version = ?, description = ?
                 WHERE id = ?',
                [
                    in_array($_POST['status'] ?? 'active', ['active','reserved','dhcp','gateway','deprecated'], true)
                        ? $_POST['status'] : 'active',
                    trim($_POST['hostname'] ?? '') ?: null,
                    (int)($_POST['device_type_id'] ?? 0) ?: null,
                    $mac !== '' ? $mac : null,
                    trim($_POST['serial_number'] ?? '') ?: null,
                    trim($_POST['os'] ?? '') ?: null,
                    trim($_POST['software_version'] ?? '') ?: null,
                    trim($_POST['description'] ?? '') ?: null,
                    $id,
                ]
            );
            Audit::log('update', 'ip_address', (string)$id, $rec['address']);
            App::flash('success', $rec['address'] . ' updated.');
            App::redirect('/?page=subnet_view&id=' . (int)$rec['subnet_id']);

        // ---------------- Discovery ----------------
        case 'discovery_run':
            Auth::requirePermission('discovery.run');
            $subnetId = (int)($_POST['subnet_id'] ?? 0);
            set_time_limit(300);
            try {
                $r = Discovery::scanSubnet($subnetId, Auth::id());
                Audit::log('discover', 'subnet', (string)$subnetId,
                    "alive {$r['alive']}/{$r['scanned']}, new {$r['new']}, changed {$r['changed']}");
                $msg = sprintf(
                    'Scan finished: %d/%d hosts responded — %d new, %d changed, %d known-but-silent. MACs: %d, hostnames: %d, SNMP: %d, topology links: %d (LLDP/CDP %d, switch ports %d, gateway ARP %d).',
                    $r['alive'], $r['scanned'], $r['new'], $r['changed'], $r['unreachable_known'],
                    $r['macs_found'], $r['names_found'], $r['snmp_found'], $r['links_found'],
                    $r['lldp_cdp_links'] ?? $r['links_found'], $r['fdb_links'] ?? 0, $r['arp_links'] ?? 0
                );
                if ($r['alive'] > 0 && $r['macs_found'] === 0) {
                    $msg .= ' No MACs were visible — the scanner is probably behind a bridged/NAT network (e.g. default Docker networking). Run the container with network_mode: host, or run bin/discover.php directly on a machine in this subnet.';
                }
                App::flash('success', $msg);
            } catch (Throwable $e) {
                App::flash('danger', 'Scan failed: ' . $e->getMessage());
            }
            App::redirect('/?page=discovery');

        case 'discovered_adopt':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            $h = Database::one('SELECT * FROM discovered_hosts WHERE id = ?', [$id]);
            if (!$h) {
                App::flash('danger', 'Discovered host not found.');
                App::redirect('/?page=discovery');
            }
            try {
                Database::exec(
                    'INSERT INTO ip_addresses (subnet_id, address, address_bin, status, hostname, mac_address, description, last_seen)
                     VALUES (?,?,?,?,?,?,?,NOW())',
                    [
                        (int)$h['subnet_id'], $h['address'], $h['address_bin'], 'active',
                        $h['hostname'], $h['mac_address'], 'Adopted from discovery',
                    ]
                );
                Database::exec('UPDATE discovered_hosts SET adopted = 1, status = "known" WHERE id = ?', [$id]);
                Audit::log('create', 'ip_address', (string)Database::lastId(), $h['address'] . ' (adopted)');
                App::flash('success', $h['address'] . ' adopted into inventory.');
            } catch (PDOException) {
                App::flash('danger', 'That IP already exists in the subnet.');
            }
            App::redirect('/?page=discovery');

        case 'discovered_delete':
            Auth::requirePermission('discovery.run');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('DELETE FROM discovered_hosts WHERE id = ?', [$id]);
            App::flash('success', 'Discovered entry removed.');
            App::redirect('/?page=discovery');

        case 'notif_read':
            Database::exec('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [Auth::id()]);
            App::redirect('/?page=' . preg_replace('/\W/', '', $_POST['back'] ?? 'dashboard'));


        // ---------------- Updates (v1.2) ----------------
        case 'site_update':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            $name = trim($_POST['name'] ?? '');
            if ($name === '') {
                App::flash('danger', 'Site name is required.');
                App::redirect('/?page=sites');
            }
            $slug = trim($_POST['slug'] ?? '');
            $slug = $slug !== '' ? $slug : strtolower(preg_replace('/[^a-z0-9]+/i', '-', $name));
            $slug = trim(preg_replace('/-+/', '-', $slug), '-');
            try {
                Database::exec(
                    'UPDATE sites SET name = ?, slug = ?, address = ?, description = ? WHERE id = ?',
                    [$name, $slug, trim($_POST['address'] ?? '') ?: null, trim($_POST['description'] ?? '') ?: null, $id]
                );
                Audit::log('update', 'site', (string)$id, $name);
                App::flash('success', 'Site updated.');
            } catch (PDOException) {
                App::flash('danger', 'A site with that name or slug already exists.');
            }
            App::redirect('/?page=sites');

        case 'vlan_update':
            Auth::requirePermission('ipam.manage');
            $id  = (int)($_POST['id'] ?? 0);
            $vid = (int)($_POST['vid'] ?? 0);
            if ($vid < 1 || $vid > 4094) {
                App::flash('danger', 'VLAN ID must be 1–4094.');
                App::redirect('/?page=vlans');
            }
            try {
                Database::exec(
                    'UPDATE vlans SET vid = ?, name = ?, site_id = ?, status = ?, description = ? WHERE id = ?',
                    [
                        $vid,
                        trim($_POST['name'] ?? ''),
                        (int)($_POST['site_id'] ?? 0) ?: null,
                        $_POST['status'] ?? 'active',
                        trim($_POST['description'] ?? '') ?: null,
                        $id,
                    ]
                );
                Audit::log('update', 'vlan', (string)$id, 'VLAN ' . $vid);
                App::flash('success', 'VLAN updated.');
            } catch (PDOException) {
                App::flash('danger', 'VLAN ID already exists at that site.');
            }
            App::redirect('/?page=vlans');

        case 'subnet_update':
            Auth::requirePermission('ipam.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec(
                'UPDATE subnets SET name = ?, vlan_id = ?, site_id = ?, gateway = ?, status = ?, description = ? WHERE id = ?',
                [
                    trim($_POST['name'] ?? '') ?: null,
                    (int)($_POST['vlan_id'] ?? 0) ?: null,
                    (int)($_POST['site_id'] ?? 0) ?: null,
                    trim($_POST['gateway'] ?? '') ?: null,
                    $_POST['status'] ?? 'active',
                    trim($_POST['description'] ?? '') ?: null,
                    $id,
                ]
            );
            Audit::log('update', 'subnet', (string)$id);
            App::flash('success', 'Subnet updated.');
            App::redirect('/?page=' . (($_POST['back'] ?? '') === 'subnet_view' ? 'subnet_view&id=' . $id : 'subnets'));

        case 'user_update':
            Auth::requirePermission('users.manage');
            $id = (int)($_POST['id'] ?? 0);
            $target = Database::one('SELECT * FROM users WHERE id = ?', [$id]);
            if (!$target) {
                App::flash('danger', 'User not found.');
                App::redirect('/?page=users');
            }
            $roleId   = (int)($_POST['role_id'] ?? $target['role_id']);
            $isActive = isset($_POST['is_active']) ? 1 : 0;
            if ($id === Auth::id()) {
                // never lock yourself out or demote yourself
                $roleId   = (int)$target['role_id'];
                $isActive = (int)$target['is_active'];
            }
            $password = (string)($_POST['password'] ?? '');
            if ($password !== '' && strlen($password) < 10) {
                App::flash('danger', 'New password must be at least 10 characters.');
                App::redirect('/?page=users');
            }
            try {
                Database::exec(
                    'UPDATE users SET email = ?, full_name = ?, role_id = ?, is_active = ? WHERE id = ?',
                    [
                        trim($_POST['email'] ?? $target['email']),
                        trim($_POST['full_name'] ?? '') ?: null,
                        $roleId,
                        $isActive,
                        $id,
                    ]
                );
                if ($password !== '') {
                    Database::exec(
                        'UPDATE users SET password_hash = ? WHERE id = ?',
                        [password_hash($password, PASSWORD_BCRYPT, ['cost' => App::config()['security']['bcrypt_cost']]), $id]
                    );
                }
                Audit::log('update', 'user', (string)$id, $target['username'] . ($password !== '' ? ' (password reset)' : ''));
                App::flash('success', 'User updated.');
            } catch (PDOException) {
                App::flash('danger', 'That email is already in use.');
            }
            App::redirect('/?page=users');

        case 'user_delete':
            Auth::requirePermission('users.manage');
            $id = (int)($_POST['id'] ?? 0);
            if ($id === Auth::id()) {
                App::flash('danger', 'You cannot delete your own account.');
                App::redirect('/?page=users');
            }
            $target = Database::one('SELECT username FROM users WHERE id = ?', [$id]);
            if ($target) {
                Database::exec('DELETE FROM users WHERE id = ?', [$id]);
                Audit::log('delete', 'user', (string)$id, $target['username']);
                App::flash('success', 'User "' . $target['username'] . '" deleted.');
            }
            App::redirect('/?page=users');


        // ---------------- SNMP credentials (v2.0) ----------------
        case 'snmp_save':
            Auth::requirePermission('snmp.manage');
            $id      = (int)($_POST['id'] ?? 0);
            $name    = trim($_POST['name'] ?? '');
            $version = ($_POST['version'] ?? '2c') === '3' ? '3' : '2c';
            if ($name === '') {
                App::flash('danger', 'Profile name is required.');
                App::redirect('/?page=snmp');
            }
            $args = [
                $name, $version,
                $version === '2c' ? (trim($_POST['community'] ?? '') ?: 'public') : null,
                $version === '3' ? (trim($_POST['sec_name'] ?? '') ?: null) : null,
                $version === '3' ? ($_POST['sec_level'] ?? 'authPriv') : null,
                $version === '3' ? ($_POST['auth_protocol'] ?? 'SHA') : null,
                $version === '3' ? (trim($_POST['auth_pass'] ?? '') ?: null) : null,
                $version === '3' ? ($_POST['priv_protocol'] ?? 'AES') : null,
                $version === '3' ? (trim($_POST['priv_pass'] ?? '') ?: null) : null,
                max(100000, (int)($_POST['timeout_us'] ?? 1000000)),
                max(0, (int)($_POST['retries'] ?? 1)),
                isset($_POST['is_default']) ? 1 : 0,
            ];
            try {
                if ($id > 0) {
                    Database::exec(
                        'UPDATE snmp_credentials SET name=?, version=?, community=?, sec_name=?, sec_level=?,
                                auth_protocol=?, auth_pass=?, priv_protocol=?, priv_pass=?, timeout_us=?, retries=?, is_default=?
                         WHERE id=?',
                        [...$args, $id]
                    );
                    Audit::log('update', 'snmp_credential', (string)$id, $name);
                } else {
                    Database::exec(
                        'INSERT INTO snmp_credentials
                            (name, version, community, sec_name, sec_level, auth_protocol, auth_pass,
                             priv_protocol, priv_pass, timeout_us, retries, is_default)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                        $args
                    );
                    $id = (int)Database::lastId();
                    Audit::log('create', 'snmp_credential', (string)$id, $name);
                }
                if (isset($_POST['is_default'])) {
                    Database::exec('UPDATE snmp_credentials SET is_default = 0 WHERE id <> ?', [$id]);
                }
                App::flash('success', 'SNMP profile saved.');
            } catch (PDOException) {
                App::flash('danger', 'A profile with that name already exists.');
            }
            App::redirect('/?page=snmp');

        case 'snmp_delete':
            Auth::requirePermission('snmp.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('UPDATE subnets SET snmp_credential_id = NULL WHERE snmp_credential_id = ?', [$id]);
            Database::exec('DELETE FROM snmp_credentials WHERE id = ?', [$id]);
            Audit::log('delete', 'snmp_credential', (string)$id);
            App::flash('success', 'SNMP profile deleted.');
            App::redirect('/?page=snmp');

        case 'snmp_test':
            Auth::requirePermission('snmp.manage');
            $host = trim($_POST['host'] ?? '');
            $cred = Database::one('SELECT * FROM snmp_credentials WHERE id = ?', [(int)($_POST['id'] ?? 0)]);
            if (!Snmp::available()) {
                App::flash('danger', 'The PHP SNMP extension is not installed (apt install php8.3-snmp / apk add php83-snmp).');
            } elseif (!$cred || !filter_var($host, FILTER_VALIDATE_IP)) {
                App::flash('danger', 'Pick a profile and enter a valid IP address to test.');
            } else {
                $info = Snmp::poll($host, $cred);
                if ($info === null) {
                    App::flash('danger', 'No SNMP response from ' . $host . ' using profile "' . $cred['name'] . '".');
                } else {
                    $n = Snmp::neighbours($host, $cred);
                    App::flash('success', sprintf(
                        'SNMP OK — %s | OS: %s %s | serial: %s | %d MAC(s) | %d neighbour(s).',
                        $info['sysname'] ?? '(no sysName)',
                        $info['os'] ?? '?', $info['version'] ?? '',
                        $info['serial'] ?? '—', count($info['macs']), count($n)
                    ));
                }
            }
            App::redirect('/?page=snmp');

        case 'subnet_snmp_bind':
            Auth::requirePermission('ipam.manage');
            $sid = (int)($_POST['subnet_id'] ?? 0);
            Database::exec('UPDATE subnets SET snmp_credential_id = ? WHERE id = ?',
                [(int)($_POST['snmp_credential_id'] ?? 0) ?: null, $sid]);
            App::flash('success', 'SNMP profile assigned to subnet.');
            App::redirect('/?page=subnet_view&id=' . $sid);

        // ---------------- Zabbix (v2.0) ----------------
        case 'zabbix_test':
            Auth::requirePermission('monitoring.view');
            try {
                App::flash('success', 'Connected to Zabbix API version ' . Zabbix::version() . '.');
            } catch (Throwable $e) {
                App::flash('danger', $e->getMessage());
            }
            App::redirect('/?page=monitoring');

        case 'zabbix_sync':
            Auth::requirePermission('monitoring.view');
            set_time_limit(300);
            try {
                $r = Zabbix::sync();
                Audit::log('sync', 'monitoring', null,
                    "hosts {$r['hosts']}, matched {$r['matched']}");
                App::flash('success', sprintf(
                    'Zabbix sync complete: %d hosts, %d IP addresses matched (%d online, %d offline).',
                    $r['hosts'], $r['matched'], $r['online'], $r['offline']
                ));
            } catch (Throwable $e) {
                App::flash('danger', 'Zabbix sync failed: ' . $e->getMessage());
            }
            App::redirect('/?page=monitoring');

        case 'zabbix_refresh':
            Auth::requirePermission('monitoring.view');
            set_time_limit(300);
            try {
                $r = Zabbix::refresh();
                Audit::log('sync', 'monitoring', null,
                    "refresh: cleared {$r['cleared']}, hosts {$r['hosts']}, matched {$r['matched']}");
                App::flash('success', sprintf(
                    'Monitoring database refreshed: %d old row(s) cleared, %d hosts synced, %d IP addresses matched (%d online, %d offline).',
                    $r['cleared'], $r['hosts'], $r['matched'], $r['online'], $r['offline']
                ));
            } catch (Throwable $e) {
                App::flash('danger', 'Zabbix refresh failed: ' . $e->getMessage());
            }
            App::redirect('/?page=monitoring');

        // ---------------- Zabbix connection settings (Monitoring page) ----------------
        // Saved to app_settings (database) so they survive container rebuilds.
        // Database values take precedence over environment / config.php.
        case 'zabbix_save':
            Auth::requirePermission('snmp.manage');
            $url      = trim($_POST['zabbix_url'] ?? '');
            $token    = trim($_POST['zabbix_token'] ?? '');
            $verify   = isset($_POST['zabbix_verify_tls']) ? '1' : '0';
            $timeout  = min(60, max(3, (int)($_POST['zabbix_timeout'] ?? 10)));
            $andTest  = isset($_POST['save_and_test']);
            if ($url === '' && $token === '') {
                Settings::delete('zabbix_url', 'zabbix_token', 'zabbix_verify_tls', 'zabbix_timeout');
                Audit::log('update', 'zabbix', null, 'connection settings cleared (fallback to env/config)');
                App::flash('success', 'Saved settings cleared — falling back to environment / config file.');
                App::redirect('/?page=monitoring');
            }
            $err = Zabbix::validate($url, $token);
            if ($err !== null) {
                App::flash('danger', $err);
                App::redirect('/?page=monitoring');
            }
            Settings::set('zabbix_url', $url);
            Settings::set('zabbix_token', $token);
            Settings::set('zabbix_verify_tls', $verify);
            Settings::set('zabbix_timeout', (string)$timeout);
            Audit::log('update', 'zabbix', null, 'connection settings saved for ' . $url);
            if ($andTest) {
                try {
                    $ver = Zabbix::version();
                    App::flash('success', 'Settings saved. Connected to Zabbix API version ' . $ver . '.');
                } catch (Throwable $e) {
                    App::flash('warning', 'Settings saved, but the connection test failed: ' . $e->getMessage());
                }
            } else {
                App::flash('success', 'Zabbix connection settings saved.');
            }
            App::redirect('/?page=monitoring');

        case 'zabbix_clear':
            Auth::requirePermission('snmp.manage');
            Settings::delete('zabbix_url', 'zabbix_token', 'zabbix_verify_tls', 'zabbix_timeout');
            Audit::log('update', 'zabbix', null, 'connection settings cleared (fallback to env/config)');
            App::flash('success', 'Saved settings cleared — falling back to environment / config file.');
            App::redirect('/?page=monitoring');

        // ---------------- Racks (v2.0) ----------------
        case 'rack_create':
            Auth::requirePermission('racks.manage');
            $name   = trim($_POST['name'] ?? '');
            $siteId = (int)($_POST['site_id'] ?? 0);
            if ($name === '' || $siteId <= 0) {
                App::flash('danger', 'Rack name and site are both required.');
                App::redirect('/?page=racks');
            }
            Database::exec(
                'INSERT INTO racks (name, site_id, room_id, u_height, description) VALUES (?,?,?,?,?)',
                [
                    $name,
                    $siteId,
                    null,
                    max(1, min(60, (int)($_POST['u_height'] ?? 42))),
                    trim($_POST['description'] ?? '') ?: null,
                ]
            );
            Audit::log('create', 'rack', (string)Database::lastId(), $name);
            App::flash('success', 'Rack created.');
            App::redirect('/?page=racks');

        case 'rack_delete':
            Auth::requirePermission('racks.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('UPDATE ip_addresses SET rack_id = NULL, rack_position = NULL WHERE rack_id = ?', [$id]);
            Database::exec('DELETE FROM racks WHERE id = ?', [$id]);
            Audit::log('delete', 'rack', (string)$id);
            App::flash('success', 'Rack deleted.');
            App::redirect('/?page=racks');

        case 'rack_mount':
            Auth::requirePermission('racks.manage');
            $ipId = (int)($_POST['ip_id'] ?? 0);
            $rack = (int)($_POST['rack_id'] ?? 0) ?: null;
            $pos  = (int)($_POST['rack_position'] ?? 0) ?: null;
            $face = ($_POST['rack_face'] ?? 'front') === 'rear' ? 'rear' : 'front';
            $rec  = Database::one('SELECT address, subnet_id FROM ip_addresses WHERE id = ?', [$ipId]);
            if (!$rec) {
                App::flash('danger', 'IP record not found.');
                App::redirect('/?page=racks');
            }
            if ($rack && $pos) {
                $r = Database::one('SELECT u_height FROM racks WHERE id = ?', [$rack]);
                if (!$r || $pos < 1 || $pos > (int)$r['u_height']) {
                    App::flash('danger', 'Position is outside the rack height.');
                    App::redirect('/?page=racks&id=' . $rack);
                }
                $clash = Database::one(
                    'SELECT address FROM ip_addresses
                     WHERE rack_id = ? AND rack_position = ? AND rack_face = ? AND id <> ?',
                    [$rack, $pos, $face, $ipId]
                );
                if ($clash) {
                    App::flash('danger', 'U' . $pos . ' is already occupied by ' . $clash['address'] . '.');
                    App::redirect('/?page=racks&id=' . $rack);
                }
            }
            Database::exec(
                'UPDATE ip_addresses SET rack_id = ?, rack_position = ?, rack_face = ? WHERE id = ?',
                [$rack, $pos, $face, $ipId]
            );
            Audit::log('update', 'ip_address', (string)$ipId,
                $rack ? ('mounted in rack #' . $rack . ' U' . $pos) : 'unmounted');
            App::flash('success', $rack ? ($rec['address'] . ' mounted at U' . $pos . '.') : ($rec['address'] . ' removed from rack.'));
            App::redirect('/?page=racks' . ($rack ? '&id=' . $rack : ''));

        // ---------------- Automation tokens (restored in v2.0) ----------------
        case 'token_create':
            Auth::requirePermission('users.manage');
            $token = bin2hex(random_bytes(32));
            Database::exec(
                'INSERT INTO api_tokens (user_id, token_hash, label) VALUES (?,?,?)',
                [Auth::id(), hash('sha256', $token), trim($_POST['label'] ?? 'Automation token')]
            );
            Audit::log('create', 'api_token', (string)Database::lastId());
            App::flash('success', 'Token created — copy it now, it is shown only once: ' . $token);
            App::redirect('/?page=users');

        case 'token_delete':
            Auth::requirePermission('users.manage');
            $id = (int)($_POST['id'] ?? 0);
            Database::exec('DELETE FROM api_tokens WHERE id = ?', [$id]);
            Audit::log('delete', 'api_token', (string)$id);
            App::flash('success', 'Token revoked.');
            App::redirect('/?page=users');


        // ---------------- Racks v3: edit + items ----------------
        case 'rack_update':
            Auth::requirePermission('racks.manage');
            $id     = (int)($_POST['id'] ?? 0);
            $name   = trim($_POST['name'] ?? '');
            $siteId = (int)($_POST['site_id'] ?? 0);
            $newH   = max(1, min(60, (int)($_POST['u_height'] ?? 42)));
            if ($name === '' || $siteId <= 0) {
                App::flash('danger', 'Rack name and site are both required.');
                App::redirect('/?page=racks&id=' . $id);
            }
            // shrinking must not orphan mounted gear
            $over = Database::one(
                'SELECT COUNT(*) c FROM rack_items WHERE rack_id = ? AND (u_position + u_size - 1) > ?',
                [$id, $newH]
            );
            if ((int)$over['c'] > 0) {
                App::flash('danger', 'Cannot shrink to ' . $newH . 'U — ' . (int)$over['c']
                    . ' mounted item(s) would fall outside the rack. Move or remove them first.');
                App::redirect('/?page=racks&id=' . $id);
            }
            Database::exec(
                'UPDATE racks SET name = ?, site_id = ?, u_height = ?, description = ? WHERE id = ?',
                [$name, $siteId, $newH, trim($_POST['description'] ?? '') ?: null, $id]
            );
            Audit::log('update', 'rack', (string)$id, $name . ' (' . $newH . 'U)');
            App::flash('success', 'Rack updated.');
            App::redirect('/?page=racks&id=' . $id);

        case 'rack_item_save':
            Auth::requirePermission('racks.manage');
            $itemId = (int)($_POST['item_id'] ?? 0);
            $rackId = (int)($_POST['rack_id'] ?? 0);
            $rack   = Database::one('SELECT * FROM racks WHERE id = ?', [$rackId]);
            if (!$rack) {
                App::flash('danger', 'Rack not found.');
                App::redirect('/?page=racks');
            }
            $pos   = (int)($_POST['u_position'] ?? 0);
            $size  = max(1, min(20, (int)($_POST['u_size'] ?? 1)));
            $face  = ($_POST['face'] ?? 'front') === 'rear' ? 'rear' : 'front';
            $ipId  = (int)($_POST['ip_id'] ?? 0) ?: null;
            $kind  = preg_replace('/[^a-z0-9 _-]/i', '', (string)($_POST['kind'] ?? 'device')) ?: 'device';
            $name  = trim($_POST['name'] ?? '');

            if ($ipId) {
                $ipRec = Database::one('SELECT address, hostname FROM ip_addresses WHERE id = ?', [$ipId]);
                if (!$ipRec) {
                    $ipId = null;
                } elseif ($name === '') {
                    $name = $ipRec['hostname'] ?: $ipRec['address'];
                }
            }
            if ($name === '') {
                App::flash('danger', 'Give the item a name, or link it to an IP record.');
                App::redirect('/?page=racks&id=' . $rackId);
            }
            if ($pos < 1 || ($pos + $size - 1) > (int)$rack['u_height']) {
                App::flash('danger', 'A ' . $size . 'U item at U' . $pos . ' does not fit in a '
                    . (int)$rack['u_height'] . 'U rack.');
                App::redirect('/?page=racks&id=' . $rackId);
            }
            // overlap check across the whole span, same face
            $clash = Database::one(
                'SELECT name, u_position, u_size FROM rack_items
                 WHERE rack_id = ? AND face = ? AND id <> ?
                   AND u_position <= ? AND (u_position + u_size - 1) >= ?
                 LIMIT 1',
                [$rackId, $face, $itemId, $pos + $size - 1, $pos]
            );
            if ($clash) {
                App::flash('danger', sprintf(
                    'U%d–U%d overlaps "%s" (U%d–U%d).',
                    $pos, $pos + $size - 1, $clash['name'],
                    (int)$clash['u_position'], (int)$clash['u_position'] + (int)$clash['u_size'] - 1
                ));
                App::redirect('/?page=racks&id=' . $rackId);
            }

            // optional photo
            $photo = null;
            $replacePhoto = false;
            if (!empty($_FILES['photo']['name'] ?? '')) {
                try {
                    $up = Uploads::store($_FILES['photo'], 'rack', Uploads::IMAGE_TYPES, Uploads::MAX_IMAGE_BYTES);
                    $photo = $up['stored_path'];
                    $replacePhoto = true;
                } catch (Throwable $e) {
                    App::flash('danger', 'Photo not saved: ' . $e->getMessage());
                    App::redirect('/?page=racks&id=' . $rackId);
                }
            }

            if ($itemId > 0) {
                $old = Database::one('SELECT photo_path FROM rack_items WHERE id = ?', [$itemId]);
                if ($replacePhoto && $old && $old['photo_path']) {
                    Uploads::delete($old['photo_path']);
                }
                Database::exec(
                    'UPDATE rack_items SET rack_id=?, ip_id=?, name=?, kind=?, u_position=?, u_size=?,
                            face=?, color=?, description=?' . ($replacePhoto ? ', photo_path=?' : '') . '
                     WHERE id = ?',
                    $replacePhoto
                        ? [$rackId, $ipId, $name, $kind, $pos, $size, $face,
                           trim($_POST['color'] ?? '') ?: null, trim($_POST['description'] ?? '') ?: null,
                           $photo, $itemId]
                        : [$rackId, $ipId, $name, $kind, $pos, $size, $face,
                           trim($_POST['color'] ?? '') ?: null, trim($_POST['description'] ?? '') ?: null,
                           $itemId]
                );
                Audit::log('update', 'rack_item', (string)$itemId, $name);
                App::flash('success', $name . ' updated.');
            } else {
                Database::exec(
                    'INSERT INTO rack_items (rack_id, ip_id, name, kind, u_position, u_size, face, color, photo_path, description)
                     VALUES (?,?,?,?,?,?,?,?,?,?)',
                    [$rackId, $ipId, $name, $kind, $pos, $size, $face,
                     trim($_POST['color'] ?? '') ?: null, $photo, trim($_POST['description'] ?? '') ?: null]
                );
                Audit::log('create', 'rack_item', (string)Database::lastId(), $name . ' U' . $pos);
                App::flash('success', $name . ' mounted at U' . $pos . ($size > 1 ? '–U' . ($pos + $size - 1) : '') . '.');
            }
            App::redirect('/?page=racks&id=' . $rackId);

        case 'rack_item_delete':
            Auth::requirePermission('racks.manage');
            $itemId = (int)($_POST['id'] ?? 0);
            $item = Database::one('SELECT rack_id, name, photo_path FROM rack_items WHERE id = ?', [$itemId]);
            if ($item) {
                Uploads::delete($item['photo_path']);
                Database::exec('DELETE FROM rack_items WHERE id = ?', [$itemId]);
                Audit::log('delete', 'rack_item', (string)$itemId, $item['name']);
                App::flash('success', $item['name'] . ' removed from the rack.');
            }
            App::redirect('/?page=racks&id=' . (int)($item['rack_id'] ?? 0));

        case 'rack_item_photo_delete':
            Auth::requirePermission('racks.manage');
            $itemId = (int)($_POST['id'] ?? 0);
            $item = Database::one('SELECT rack_id, photo_path FROM rack_items WHERE id = ?', [$itemId]);
            if ($item && $item['photo_path']) {
                Uploads::delete($item['photo_path']);
                Database::exec('UPDATE rack_items SET photo_path = NULL WHERE id = ?', [$itemId]);
                App::flash('success', 'Photo removed.');
            }
            App::redirect('/?page=racks&id=' . (int)($item['rack_id'] ?? 0));

        // ---------------- Rack designer (v5.0) — JSON drag/move/resize ----------------
        case 'rack_api':
            Auth::requirePermission('racks.manage');
            header('Content-Type: application/json; charset=utf-8');
            $respond = static function (array $payload, int $code = 200): void {
                http_response_code($code);
                echo json_encode($payload);
                exit;
            };

            $op     = $_POST['op'] ?? '';
            $rackId = (int)($_POST['rack_id'] ?? 0);
            $rack   = Database::one('SELECT * FROM racks WHERE id = ?', [$rackId]);
            if (!$rack) {
                $respond(['ok' => false, 'error' => 'Rack not found.'], 404);
            }
            $H = (int)$rack['u_height'];

            // Enriched item row — mirrors the elevation query so the client can
            // render the faceplate and metadata straight from the response.
            $fetchItem = static function (int $id) use ($rackId) {
                return Database::one(
                    'SELECT ri.id, ri.name, ri.kind, ri.u_position, ri.u_size, ri.face,
                            ri.color, ri.description, ri.ip_id, ri.device_type_id,
                            i.address, i.subnet_id,
                            TRIM(CONCAT(
                                COALESCE(v.name, vd.name, ""), " ",
                                COALESCE(dt.model, dtd.model, "")
                            )) AS type_label,
                            COALESCE(NULLIF(ri.photo_path, ""), dt.image_path, dtd.image_path) AS display_image
                     FROM rack_items ri
                     LEFT JOIN ip_addresses i ON i.id = ri.ip_id
                     LEFT JOIN device_types dt ON dt.id = i.device_type_id
                     LEFT JOIN vendors v ON v.id = dt.vendor_id
                     LEFT JOIN device_types dtd ON dtd.id = ri.device_type_id
                     LEFT JOIN vendors vd ON vd.id = dtd.vendor_id
                     WHERE ri.id = ? AND ri.rack_id = ?',
                    [$id, $rackId]
                );
            };

            // Fit + overlap check for a candidate placement on one face.
            $checkPlacement = static function (int $pos, int $size, string $face, int $exclude) use ($rackId, $H) {
                if ($pos < 1 || $size < 1 || ($pos + $size - 1) > $H) {
                    return 'A ' . $size . 'U item at U' . $pos . " doesn't fit in a " . $H . 'U rack.';
                }
                $clash = Database::one(
                    'SELECT name, u_position, u_size FROM rack_items
                     WHERE rack_id = ? AND face = ? AND id <> ?
                       AND u_position <= ? AND (u_position + u_size - 1) >= ?
                     LIMIT 1',
                    [$rackId, $face, $exclude, $pos + $size - 1, $pos]
                );
                if ($clash) {
                    return sprintf('U%d–U%d overlaps "%s" (U%d–U%d).',
                        $pos, $pos + $size - 1, $clash['name'],
                        (int)$clash['u_position'], (int)$clash['u_position'] + (int)$clash['u_size'] - 1);
                }
                return null;
            };

            $normFace = static fn($f) => (($f ?? 'front') === 'rear' ? 'rear' : 'front');

            switch ($op) {
                case 'create':
                    $pos   = (int)($_POST['u_position'] ?? 0);
                    $size  = max(1, min(20, (int)($_POST['u_size'] ?? 1)));
                    $face  = $normFace($_POST['face'] ?? 'front');
                    $kind  = preg_replace('/[^a-z0-9 _-]/i', '', (string)($_POST['kind'] ?? 'device')) ?: 'device';
                    $ipId  = (int)($_POST['ip_id'] ?? 0) ?: null;
                    $dtId  = (int)($_POST['device_type_id'] ?? 0) ?: null;
                    $name  = trim($_POST['name'] ?? '');

                    if ($ipId) {
                        $ipRec = Database::one('SELECT address, hostname FROM ip_addresses WHERE id = ?', [$ipId]);
                        if (!$ipRec) {
                            $ipId = null;
                        } elseif ($name === '') {
                            $name = $ipRec['hostname'] ?: $ipRec['address'];
                        }
                    }
                    if ($dtId) {
                        $dtRec = Database::one(
                            'SELECT dt.model, dt.u_height, v.name AS vendor
                             FROM device_types dt LEFT JOIN vendors v ON v.id = dt.vendor_id
                             WHERE dt.id = ?', [$dtId]);
                        if (!$dtRec) {
                            $dtId = null;
                        } elseif ($name === '') {
                            $name = trim(($dtRec['vendor'] ?? '') . ' ' . $dtRec['model']);
                        }
                    }
                    if ($name === '') {
                        $respond(['ok' => false, 'error' => 'Give the item a name, or link an IP record or model.'], 422);
                    }
                    if ($err = $checkPlacement($pos, $size, $face, 0)) {
                        $respond(['ok' => false, 'error' => $err], 409);
                    }
                    Database::exec(
                        'INSERT INTO rack_items (rack_id, ip_id, device_type_id, name, kind, u_position, u_size, face, color, description)
                         VALUES (?,?,?,?,?,?,?,?,?,?)',
                        [$rackId, $ipId, $dtId, $name, $kind, $pos, $size, $face,
                         trim($_POST['color'] ?? '') ?: null, trim($_POST['description'] ?? '') ?: null]
                    );
                    $id = (int)Database::lastId();
                    Audit::log('create', 'rack_item', (string)$id, $name . ' U' . $pos);
                    $respond(['ok' => true, 'item' => $fetchItem($id)]);
                    // no break — respond() exits

                case 'move':
                case 'resize':
                    $id  = (int)($_POST['id'] ?? 0);
                    $cur = Database::one('SELECT * FROM rack_items WHERE id = ? AND rack_id = ?', [$id, $rackId]);
                    if (!$cur) {
                        $respond(['ok' => false, 'error' => 'Item not found.'], 404);
                    }
                    $pos  = (int)($_POST['u_position'] ?? $cur['u_position']);
                    $size = max(1, min(20, (int)($_POST['u_size'] ?? $cur['u_size'])));
                    $face = $normFace($_POST['face'] ?? $cur['face']);
                    if ($err = $checkPlacement($pos, $size, $face, $id)) {
                        $respond(['ok' => false, 'error' => $err], 409);
                    }
                    Database::exec(
                        'UPDATE rack_items SET u_position = ?, u_size = ?, face = ? WHERE id = ?',
                        [$pos, $size, $face, $id]
                    );
                    Audit::log('update', 'rack_item', (string)$id, $cur['name'] . ' → U' . $pos);
                    $respond(['ok' => true, 'item' => $fetchItem($id)]);

                case 'update':
                    $id  = (int)($_POST['id'] ?? 0);
                    $cur = Database::one('SELECT * FROM rack_items WHERE id = ? AND rack_id = ?', [$id, $rackId]);
                    if (!$cur) {
                        $respond(['ok' => false, 'error' => 'Item not found.'], 404);
                    }
                    $kind = preg_replace('/[^a-z0-9 _-]/i', '', (string)($_POST['kind'] ?? $cur['kind'])) ?: 'device';
                    $name = trim($_POST['name'] ?? (string)$cur['name']);
                    $ipId = array_key_exists('ip_id', $_POST)
                        ? ((int)$_POST['ip_id'] ?: null)
                        : ($cur['ip_id'] !== null ? (int)$cur['ip_id'] : null);
                    if ($ipId) {
                        $ipRec = Database::one('SELECT address, hostname FROM ip_addresses WHERE id = ?', [$ipId]);
                        if (!$ipRec) {
                            $ipId = null;
                        } elseif ($name === '') {
                            $name = $ipRec['hostname'] ?: $ipRec['address'];
                        }
                    }
                    if ($name === '') {
                        $respond(['ok' => false, 'error' => 'Give the item a name.'], 422);
                    }
                    Database::exec(
                        'UPDATE rack_items SET name = ?, kind = ?, ip_id = ?, color = ?, description = ? WHERE id = ?',
                        [$name, $kind, $ipId, trim($_POST['color'] ?? '') ?: null,
                         trim($_POST['description'] ?? '') ?: null, $id]
                    );
                    Audit::log('update', 'rack_item', (string)$id, $name);
                    $respond(['ok' => true, 'item' => $fetchItem($id)]);

                case 'delete':
                    $id   = (int)($_POST['id'] ?? 0);
                    $item = Database::one('SELECT name, photo_path FROM rack_items WHERE id = ? AND rack_id = ?', [$id, $rackId]);
                    if ($item) {
                        Uploads::delete($item['photo_path']);
                        Database::exec('DELETE FROM rack_items WHERE id = ?', [$id]);
                        Audit::log('delete', 'rack_item', (string)$id, $item['name']);
                    }
                    $respond(['ok' => true, 'id' => $id]);

                default:
                    $respond(['ok' => false, 'error' => 'Unknown operation.'], 400);
            }

        // ---------------- Monitoring auto-sync ----------------
        case 'monitoring_interval':
            Auth::requirePermission('monitoring.view');
            $m = (int)($_POST['minutes'] ?? 0);
            $allowed = [0, 5, 10, 15, 30, 60];
            Settings::set('monitoring_auto_sync_minutes', (string)(in_array($m, $allowed, true) ? $m : 0));
            App::flash('success', $m > 0
                ? 'Auto-sync enabled — every ' . $m . ' minutes while this page is open.'
                : 'Auto-sync disabled.');
            App::redirect('/?page=monitoring');

        // ---------------- Documentation ----------------
        case 'doc_upload':
            Auth::requirePermission('docs.manage');
            $entityType = in_array($_POST['entity_type'] ?? '', ['ip_address', 'rack', 'site'], true)
                ? $_POST['entity_type'] : 'ip_address';
            $entityId = (int)($_POST['entity_id'] ?? 0);
            $back     = $_POST['back'] ?? '/?page=documents';
            $category = in_array($_POST['category'] ?? '', Uploads::CATEGORIES, true)
                ? $_POST['category'] : 'document';
            if ($entityId <= 0) {
                App::flash('danger', 'Choose what this document belongs to.');
                App::redirect($back);
            }
            try {
                $up = Uploads::store($_FILES['file'] ?? [], 'docs', Uploads::DOC_TYPES, Uploads::MAX_DOC_BYTES);
                Database::exec(
                    'INSERT INTO attachments
                        (entity_type, entity_id, category, title, filename, stored_path, mime_type, size_bytes, notes, uploaded_by)
                     VALUES (?,?,?,?,?,?,?,?,?,?)',
                    [
                        $entityType, $entityId, $category,
                        trim($_POST['title'] ?? '') ?: null,
                        $up['filename'], $up['stored_path'], $up['mime'], $up['size'],
                        trim($_POST['notes'] ?? '') ?: null,
                        Auth::id(),
                    ]
                );
                Audit::log('create', 'attachment', (string)Database::lastId(), $up['filename']);
                App::flash('success', 'Uploaded "' . $up['filename'] . '".');
            } catch (Throwable $e) {
                App::flash('danger', $e->getMessage());
            }
            App::redirect($back);

        case 'doc_delete':
            Auth::requirePermission('docs.manage');
            $id  = (int)($_POST['id'] ?? 0);
            $doc = Database::one('SELECT * FROM attachments WHERE id = ?', [$id]);
            if ($doc) {
                Uploads::delete($doc['stored_path']);
                Database::exec('DELETE FROM attachments WHERE id = ?', [$id]);
                Audit::log('delete', 'attachment', (string)$id, $doc['filename']);
                App::flash('success', 'Deleted "' . $doc['filename'] . '".');
            }
            App::redirect($_POST['back'] ?? '/?page=documents');

        // ---------------- Backup / restore ----------------
        case 'backup_restore':
            Auth::requirePermission('backup.manage');
            set_time_limit(600);
            if (($_POST['confirm'] ?? '') !== 'RESTORE') {
                App::flash('danger', 'Type RESTORE in the confirmation box to proceed.');
                App::redirect('/?page=backup');
            }
            $f = $_FILES['archive'] ?? null;
            if (!$f || ($f['error'] ?? 1) !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'] ?? '')) {
                App::flash('danger', 'Select a backup file to restore.');
                App::redirect('/?page=backup');
            }
            $tmp = sys_get_temp_dir() . '/dvipam-restore-' . bin2hex(random_bytes(6));
            $ext = str_ends_with(strtolower((string)$f['name']), '.sql') ? '.sql' : '.tar.gz';
            $tmp .= $ext;
            if (!@move_uploaded_file($f['tmp_name'], $tmp)) {
                App::flash('danger', 'Could not read the uploaded backup.');
                App::redirect('/?page=backup');
            }
            try {
                $r = Backup::restore($tmp, isset($_POST['restore_uploads']));
                @unlink($tmp);
                Audit::log('restore', 'system', null,
                    $r['statements'] . ' statements, ' . $r['uploads'] . ' files');
                App::flash('success', sprintf(
                    'Restore complete: %d SQL statements applied, %d uploaded file(s) restored. Sign in again if anything looks stale.',
                    $r['statements'], $r['uploads']
                ));
            } catch (Throwable $e) {
                @unlink($tmp);
                App::flash('danger', 'Restore failed: ' . $e->getMessage()
                    . ' — the database may be partially restored; re-run with a known-good backup.');
            }
            App::redirect('/?page=backup');


        // ---------------- Model image search (v4) ----------------
        case 'model_image_upload':
            Auth::requirePermission('devices.manage');
            $id   = (int)($_POST['id'] ?? 0);
            $back = $_POST['back'] ?? '/?page=devices';
            try {
                $up  = Uploads::store($_FILES['image'] ?? [], 'models', Uploads::IMAGE_TYPES, Uploads::MAX_IMAGE_BYTES);
                $old = Database::one('SELECT image_path FROM device_types WHERE id = ?', [$id]);
                if ($old && $old['image_path']) {
                    Uploads::delete($old['image_path']);
                }
                Database::exec(
                    'UPDATE device_types SET image_path = ?, image_source = ?, image_credit = ? WHERE id = ?',
                    [$up['stored_path'], 'upload', null, $id]
                );
                Audit::log('update', 'device_type', (string)$id, 'model image uploaded');
                App::flash('success', 'Model image uploaded.');
            } catch (Throwable $e) {
                App::flash('danger', $e->getMessage());
            }
            App::redirect($back);

        case 'model_image_delete':
            Auth::requirePermission('devices.manage');
            $id  = (int)($_POST['id'] ?? 0);
            $row = Database::one('SELECT image_path FROM device_types WHERE id = ?', [$id]);
            if ($row && $row['image_path']) {
                Uploads::delete($row['image_path']);
            }
            Database::exec('UPDATE device_types SET image_path = NULL, image_source = NULL, image_credit = NULL WHERE id = ?', [$id]);
            App::flash('success', 'Model image removed.');
            App::redirect($_POST['back'] ?? '/?page=devices');

        default:
            http_response_code(400);
            exit('Unknown action.');
    }
}

// ------------------------------------------------------------------
// CSV export (GET, permission-gated)
// ------------------------------------------------------------------
if ($page === 'export') {
    Auth::requirePermission('ipam.view');
    $what = $_GET['what'] ?? 'ips';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="darkveda_' . preg_replace('/\W/', '', $what) . '_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    if ($what === 'subnets') {
        fputcsv($out, ['cidr', 'name', 'vlan', 'site', 'status', 'description']);
        foreach (Database::q(
            'SELECT s.cidr, s.name, v.vid AS vlan, st.name AS site, s.status, s.description
             FROM subnets s
             LEFT JOIN vlans v ON v.id = s.vlan_id
             LEFT JOIN sites st ON st.id = s.site_id
             ORDER BY s.network_bin'
        ) as $r) {
            fputcsv($out, $r);
        }
    } else {
        fputcsv($out, ['address', 'subnet', 'status', 'hostname', 'device', 'mac', 'serial', 'os', 'software_version', 'description']);
        foreach (Database::q(
            'SELECT i.address, s.cidr AS subnet, i.status, i.hostname,
                    TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS device, i.mac_address, i.serial_number, i.os, i.software_version, i.description
             FROM ip_addresses i
             JOIN subnets s ON s.id = i.subnet_id
             LEFT JOIN device_types dt ON dt.id = i.device_type_id
             LEFT JOIN vendors v ON v.id = dt.vendor_id
             ORDER BY i.address_bin'
        ) as $r) {
            fputcsv($out, $r);
        }
    }
    Audit::log('export', $what);
    exit;
}

// ------------------------------------------------------------------
// Topology snapshot as JSON (GET, permission-gated) — powers the
// Refresh button on the Topology page (map + stats + table, no reload)
// ------------------------------------------------------------------
if ($page === 'topology' && ($_GET['format'] ?? '') === 'json') {
    Auth::requirePermission('topology.view');
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo json_encode(Topology::snapshot(), JSON_UNESCAPED_SLASHES);
    exit;
}

// ------------------------------------------------------------------
// Page routing (GET)
// ------------------------------------------------------------------
$publicPages = ['login'];
if (!in_array($page, $publicPages, true)) {
    Auth::requirePermission();
}

switch ($page) {
    case 'login':
        if (Auth::check()) {
            App::redirect('/?page=dashboard');
        }
        require dirname(__DIR__) . '/pages/login.php';
        break;

    case 'dashboard':
        Auth::requirePermission('dashboard.view');
        App::render('dashboard', ['title' => 'Dashboard']);
        break;

    case 'subnets':
        Auth::requirePermission('ipam.view');
        App::render('subnets', ['title' => 'Subnets']);
        break;

    case 'subnet_view':
        Auth::requirePermission('ipam.view');
        App::render('subnet_view', ['title' => 'Subnet Detail']);
        break;

    case 'vlans':
        Auth::requirePermission('ipam.view');
        App::render('vlans', ['title' => 'VLANs']);
        break;

    case 'devices':
        Auth::requirePermission('devices.view');
        App::render('devices', ['title' => 'Device Types']);
        break;

    case 'users':
        Auth::requirePermission('users.manage');
        App::render('users', ['title' => 'Users']);
        break;

    case 'audit':
        Auth::requirePermission('audit.view');
        App::render('audit', ['title' => 'Audit Log']);
        break;


    case 'sites':
        Auth::requirePermission('ipam.view');
        App::render('sites', ['title' => 'Sites']);
        break;

    case 'discovery':
        Auth::requirePermission('discovery.view');
        App::render('discovery', ['title' => 'Discovery']);
        break;


    case 'topology':
        Auth::requirePermission('topology.view');
        App::render('topology', ['title' => 'Gateway ARP Topology']);
        break;

    case 'racks':
        Auth::requirePermission('racks.view');
        App::render('racks', ['title' => 'Racks']);
        break;

    case 'monitoring':
        Auth::requirePermission('monitoring.view');
        App::render('monitoring', ['title' => 'Monitoring']);
        break;

    case 'snmp':
        Auth::requirePermission('snmp.manage');
        App::render('snmp', ['title' => 'SNMP Profiles']);
        break;


    case 'rack3d':
        Auth::requirePermission('racks.view');
        App::render('rack3d', ['title' => '3D Server Room']);
        break;

    case 'documents':
        Auth::requirePermission('docs.view');
        App::render('documents', ['title' => 'Documentation']);
        break;

    case 'backup':
        Auth::requirePermission('backup.manage');
        App::render('backup', ['title' => 'Backup & Restore']);
        break;

    case 'doc_download':
        Auth::requirePermission('docs.view');
        $doc = Database::one('SELECT * FROM attachments WHERE id = ?', [(int)($_GET['id'] ?? 0)]);
        $abs = $doc ? Uploads::absolutePath($doc['stored_path']) : null;
        if (!$abs) {
            http_response_code(404);
            App::render('404', ['title' => 'Not found']);
            break;
        }
        // always download rather than render: SVG/HTML could otherwise run in-origin
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($abs));
        header('Content-Disposition: attachment; filename="' . str_replace('"', '', $doc['filename']) . '"');
        header("Content-Security-Policy: default-src 'none'; sandbox");
        header('X-Content-Type-Options: nosniff');
        readfile($abs);
        exit;

    case 'backup_download':
        Auth::requirePermission('backup.manage');
        set_time_limit(600);
        try {
            $bk = Backup::create(
                isset($_GET['uploads']),
                isset($_GET['config'])
            );
        } catch (Throwable $e) {
            App::flash('danger', 'Backup failed: ' . $e->getMessage());
            App::redirect('/?page=backup');
        }
        Audit::log('backup', 'system', null, $bk['name']);
        header('Content-Type: ' . $bk['mime']);
        header('Content-Length: ' . filesize($bk['path']));
        header('Content-Disposition: attachment; filename="' . $bk['name'] . '"');
        readfile($bk['path']);
        Backup::cleanup($bk['path']);
        exit;


    default:
        http_response_code(404);
        App::render('404', ['title' => 'Not Found']);
}
