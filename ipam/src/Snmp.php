<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * DarkVeda IPAM — SNMP client (v2c and v3).
 *
 * Wraps PHP's SNMP extension. Every method degrades gracefully when the
 * extension is missing or a host does not answer, so discovery never fails
 * because of SNMP.
 *
 * Collected per host:
 *   sysName, sysDescr, sysObjectID, sysUpTime   (identity / OS / version)
 *   entPhysicalSerialNum                        (chassis serial)
 *   ifPhysAddress                               (MAC addresses)
 *   lldpRemTable / cdpCacheTable                (topology neighbours)
 */
final class Snmp
{
    // Standard OIDs
    private const OID_SYS_DESCR    = '.1.3.6.1.2.1.1.1.0';
    private const OID_SYS_OBJECTID = '.1.3.6.1.2.1.1.2.0';
    private const OID_SYS_UPTIME   = '.1.3.6.1.2.1.1.3.0';
    private const OID_SYS_NAME     = '.1.3.6.1.2.1.1.5.0';
    private const OID_IF_PHYSADDR  = '.1.3.6.1.2.1.2.2.1.6';
    private const OID_IF_NAME      = '.1.3.6.1.2.1.31.1.1.1.1';
    private const OID_IF_DESCR     = '.1.3.6.1.2.1.2.2.1.2';
    private const OID_ENT_SERIAL   = '.1.3.6.1.2.1.47.1.1.1.1.11';

    // BRIDGE-MIB dot1dTpFdbTable (.1.3.6.1.2.1.17.4.3.1.x) + Q-BRIDGE-MIB
    // dot1qTpFdbTable (.1.3.6.1.2.1.17.7.1.2.2.1.x): learned MAC -> bridge port
    private const OID_FDB_ADDRESS   = '.1.3.6.1.2.1.17.4.3.1.1';
    private const OID_FDB_PORT      = '.1.3.6.1.2.1.17.4.3.1.2';
    private const OID_QFDB_PORT     = '.1.3.6.1.2.1.17.7.1.2.2.1.2';
    private const OID_BASE_PORT_IDX = '.1.3.6.1.2.1.17.1.4.1.2';

    // IP-MIB ARP tables: ipNetToMediaTable + ipNetToPhysicalTable
    private const OID_ARP_PHYSADDR  = '.1.3.6.1.2.1.4.22.1.2';
    private const OID_NTPPHYSADDR   = '.1.3.6.1.2.1.4.35.1.4';
    // IP-MIB ipAddrTable: every IPv4 address assigned to the device itself.
    // Used to recognise that 192.168.10.1/20.1/30.1/... are one physical box,
    // so topology stores a single management IP instead of one node per VLAN.
    private const OID_IP_AD_ENT_ADDR = '.1.3.6.1.2.1.4.20.1.1';

    // LLDP-MIB (.1.0.8802.1.1.2.1.4.1.1.x)
    private const OID_LLDP_REM_PORTID   = '.1.0.8802.1.1.2.1.4.1.1.7';
    private const OID_LLDP_REM_PORTDESC = '.1.0.8802.1.1.2.1.4.1.1.8';
    private const OID_LLDP_REM_SYSNAME  = '.1.0.8802.1.1.2.1.4.1.1.9';
    private const OID_LLDP_REM_SYSDESC  = '.1.0.8802.1.1.2.1.4.1.1.10';
    private const OID_LLDP_LOC_PORTID   = '.1.0.8802.1.1.2.1.3.7.1.3';
    // LLDP-MIB lldpRemManAddrTable: remote management addresses, so LLDP
    // neighbours can be resolved to IPs (index: timeMark.localPort.idx.subtype.addr)
    private const OID_LLDP_REM_MGMT     = '.1.0.8802.1.1.2.1.4.2.1.3';

    // CISCO-CDP-MIB (.1.3.6.1.4.1.9.9.23.1.2.1.1.x)
    private const OID_CDP_DEVICEID   = '.1.3.6.1.4.1.9.9.23.1.2.1.1.6';
    private const OID_CDP_DEVICEPORT = '.1.3.6.1.4.1.9.9.23.1.2.1.1.7';
    private const OID_CDP_PLATFORM   = '.1.3.6.1.4.1.9.9.23.1.2.1.1.8';
    private const OID_CDP_ADDRESS    = '.1.3.6.1.4.1.9.9.23.1.2.1.1.4';

    public static function available(): bool
    {
        return class_exists('\SNMP');
    }

    /**
     * Build a configured \SNMP session for a credential row, or null.
     * @param array<string,mixed> $cred row from snmp_credentials
     */
    public static function session(string $host, array $cred): ?\SNMP
    {
        if (!self::available()) {
            return null;
        }
        try {
            if (($cred['version'] ?? '2c') === '3') {
                $s = new \SNMP(\SNMP::VERSION_3, $host, (string)($cred['sec_name'] ?? ''),
                    (int)($cred['timeout_us'] ?? 1000000), (int)($cred['retries'] ?? 1));
                $s->setSecurity(
                    (string)($cred['sec_level'] ?? 'noAuthNoPriv'),
                    (string)($cred['auth_protocol'] ?? ''),
                    (string)($cred['auth_pass'] ?? ''),
                    (string)($cred['priv_protocol'] ?? ''),
                    (string)($cred['priv_pass'] ?? '')
                );
            } else {
                $s = new \SNMP(\SNMP::VERSION_2c, $host, (string)($cred['community'] ?? 'public'),
                    (int)($cred['timeout_us'] ?? 1000000), (int)($cred['retries'] ?? 1));
            }
            $s->oid_output_format = \SNMP_OID_OUTPUT_NUMERIC;
            $s->valueretrieval    = \SNMP_VALUE_PLAIN;
            $s->exceptions_enabled = 0;
            return $s;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Poll one host. Returns null when the host does not answer SNMP.
     * @return array{sysname:?string,sysdescr:?string,serial:?string,os:?string,version:?string,macs:string[],uptime:?int}|null
     */
    public static function poll(string $host, array $cred): ?array
    {
        $s = self::session($host, $cred);
        if (!$s) {
            return null;
        }

        $name = self::get($s, self::OID_SYS_NAME);
        $desc = self::get($s, self::OID_SYS_DESCR);
        if ($name === null && $desc === null) {
            $s->close();
            return null;   // no SNMP response at all
        }

        $uptime = self::get($s, self::OID_SYS_UPTIME);
        $serial = null;
        foreach (self::walk($s, self::OID_ENT_SERIAL) as $v) {
            $v = trim((string)$v);
            if ($v !== '') { $serial = $v; break; }
        }

        $macs = [];
        foreach (self::walk($s, self::OID_IF_PHYSADDR) as $v) {
            $mac = self::normaliseMac((string)$v);
            if ($mac && $mac !== '00:00:00:00:00:00') {
                $macs[] = $mac;
            }
        }

        [$os, $ver] = self::parseSysDescr((string)($desc ?? ''));
        $s->close();

        return [
            'sysname'  => $name !== null ? trim((string)$name) : null,
            'sysdescr' => $desc !== null ? trim((string)$desc) : null,
            'serial'   => $serial,
            'os'       => $os,
            'version'  => $ver,
            'macs'     => array_values(array_unique($macs)),
            'uptime'   => $uptime !== null ? (int)((int)$uptime / 100) : null,
        ];
    }

    /**
     * Collect LLDP and CDP neighbours from one host.
     * @return array<int, array{protocol:string,local_port:?string,remote_name:?string,remote_port:?string,remote_ip:?string,remote_descr:?string}>
     */
    public static function neighbours(string $host, array $cred): array
    {
        $s = self::session($host, $cred);
        if (!$s) {
            return [];
        }
        $out = [];

        // ---- LLDP ----
        $sysnames = self::walk($s, self::OID_LLDP_REM_SYSNAME);
        $portids  = self::walk($s, self::OID_LLDP_REM_PORTID);
        $portdesc = self::walk($s, self::OID_LLDP_REM_PORTDESC);
        $sysdesc  = self::walk($s, self::OID_LLDP_REM_SYSDESC);
        $locports = self::walk($s, self::OID_LLDP_LOC_PORTID);
        $mgmtByPort = self::lldpMgmtAddrs($s);

        foreach ($sysnames as $oid => $remoteName) {
            // index tail: timeMark.localPortNum.index
            $parts = explode('.', trim($oid, '.'));
            $localPortNum = $parts[count($parts) - 2] ?? null;
            $suffix = self::indexSuffix($oid, self::OID_LLDP_REM_SYSNAME);

            $out[] = [
                'protocol'     => 'lldp',
                'local_port'   => self::matchBySuffix($locports, '.' . $localPortNum)
                                  ?? ($localPortNum !== null ? 'port ' . $localPortNum : null),
                'remote_name'  => trim((string)$remoteName) ?: null,
                'remote_port'  => self::pickSuffix($portdesc, $suffix) ?? self::pickSuffix($portids, $suffix),
                'remote_ip'    => ($localPortNum !== null && isset($mgmtByPort[(int)$localPortNum]))
                                  ? $mgmtByPort[(int)$localPortNum] : null,
                'remote_descr' => self::truncate(self::pickSuffix($sysdesc, $suffix)),
            ];
        }

        // ---- CDP ----
        $cdpIds   = self::walk($s, self::OID_CDP_DEVICEID);
        $cdpPorts = self::walk($s, self::OID_CDP_DEVICEPORT);
        $cdpPlat  = self::walk($s, self::OID_CDP_PLATFORM);
        $cdpAddr  = self::walk($s, self::OID_CDP_ADDRESS);
        $ifNames  = self::walk($s, self::OID_IF_NAME);

        foreach ($cdpIds as $oid => $remoteName) {
            $suffix = self::indexSuffix($oid, self::OID_CDP_DEVICEID);
            $ifIndex = explode('.', trim($suffix, '.'))[0] ?? null;
            $out[] = [
                'protocol'     => 'cdp',
                'local_port'   => $ifIndex !== null
                                  ? (self::matchBySuffix($ifNames, '.' . $ifIndex) ?? 'if ' . $ifIndex)
                                  : null,
                'remote_name'  => trim((string)$remoteName) ?: null,
                'remote_port'  => self::pickSuffix($cdpPorts, $suffix),
                'remote_ip'    => self::hexToIp(self::pickSuffixRaw($cdpAddr, $suffix)),
                'remote_descr' => self::truncate(self::pickSuffix($cdpPlat, $suffix)),
            ];
        }

        $s->close();
        return array_values(array_filter($out, fn($n) => ($n['remote_name'] ?? '') !== ''));
    }

    /**
     * LLDP remote management addresses keyed by local port number.
     * Lets LLDP neighbours resolve to IPs (managed nodes) instead of
     * name-only ghosts. @return array<int,string> localPortNum => ip
     */
    private static function lldpMgmtAddrs(\SNMP $s): array
    {
        $out = [];
        foreach (self::walk($s, self::OID_LLDP_REM_MGMT) as $oid => $v) {
            $parsed = self::parseMgmtAddrTail(self::oidTail($oid, self::OID_LLDP_REM_MGMT));
            if ($parsed !== null) {
                [$localPort, $ip] = $parsed;
                $out[$localPort] ??= $ip;
            }
        }
        return $out;
    }

    /**
     * Parse one lldpRemManAddrTable index tail
     * (timeMark.localPort.index.addrSubtype.addr...) into port + IP.
     * Some agents (e.g. MikroTik/HP) insert an address-length sub-identifier
     * before the address bytes — detected and stripped when the first byte
     * equals the remaining byte count.
     * @param int[] $tail @return array{0:int,1:string}|null
     */
    private static function parseMgmtAddrTail(array $tail): ?array
    {
        // timeMark.localPort.index.addrSubtype.addr...
        if (count($tail) < 4) {
            return null;
        }
        $localPort = (int)$tail[1];
        $subtype   = (int)$tail[3];
        $addr      = array_slice($tail, 4);
        // Optional length prefix: first byte == number of bytes after it.
        // Tried first, with the raw bytes as fallback, so a genuine 3.x.x.x
        // address (first byte 3, four bytes total) is never mis-stripped.
        $candidates = [$addr];
        if (count($addr) >= 2 && $addr[0] === count($addr) - 1) {
            $candidates = [array_slice($addr, 1), $addr];
        }
        foreach ($candidates as $bytes) {
            $ip = self::mgmtBytesToIp($subtype, $bytes);
            if ($ip !== null) {
                return [$localPort, $ip];
            }
        }
        return null;
    }

    /** @param int[] $bytes */
    private static function mgmtBytesToIp(int $subtype, array $bytes): ?string
    {
        $ip = null;
        if ($subtype === 1 && count($bytes) >= 4) {          // IPv4
            $ip = implode('.', array_slice($bytes, 0, 4));
        } elseif ($subtype === 2 && count($bytes) >= 16) {   // IPv6
            $ip = @inet_ntop(pack('C*', ...array_slice($bytes, 0, 16))) ?: null;
        }
        if ($ip === null || $ip === false || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }
        return $ip;
    }

    /**
     * All IPv4 addresses assigned to the device itself (ipAddrTable).
     * @return string[]
     */
    public static function deviceIps(string $host, array $cred): array
    {
        $s = self::session($host, $cred);
        if (!$s) {
            return [];
        }
        $out = [];
        foreach (self::walk($s, self::OID_IP_AD_ENT_ADDR) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_IP_AD_ENT_ADDR);
            if (count($tail) < 4) {
                continue;
            }
            $ip = implode('.', array_slice($tail, -4));
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $out[] = $ip;
            }
        }
        $s->close();
        return array_values(array_unique($out));
    }

    /**
     * Bridge forwarding table: learned MAC -> local switch port.
     *
     * Reads both BRIDGE-MIB dot1dTpFdbTable and Q-BRIDGE-MIB dot1qTpFdbTable
     * (per-VLAN), so every L2-connected device — not just LLDP speakers —
     * can be placed on the topology map.
     * @return array<int, array{mac:string,port:?string}>>
     */
    public static function fdb(string $host, array $cred): array
    {
        $s = self::session($host, $cred);
        if (!$s) {
            return [];
        }
        // bridge port number -> MAC (dot1d: suffix is 6 MAC bytes)
        $ports = [];
        foreach (self::walk($s, self::OID_FDB_PORT) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_FDB_PORT);
            if (count($tail) < 6) {
                continue;
            }
            $mac = self::macFromOid(array_slice($tail, -6));
            $p = (int)$v;
            if ($mac !== null && $p > 0 && !self::isMulticastMac($mac)) {
                $ports[$mac] = $p;
            }
        }
        // Q-BRIDGE variant: suffix is vlan + 6 MAC bytes
        foreach (self::walk($s, self::OID_QFDB_PORT) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_QFDB_PORT);
            if (count($tail) < 7) {
                continue;
            }
            $mac = self::macFromOid(array_slice($tail, -6));
            $p = (int)$v;
            if ($mac !== null && $p > 0 && !self::isMulticastMac($mac)) {
                $ports[$mac] ??= $p;
            }
        }
        if (!$ports) {
            $s->close();
            return [];
        }

        // bridge port -> ifIndex -> interface name
        $portIf = [];
        foreach (self::walk($s, self::OID_BASE_PORT_IDX) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_BASE_PORT_IDX);
            if ($tail) {
                $portIf[(int)end($tail)] = (int)$v;
            }
        }
        $names = self::ifNames($s);
        $s->close();

        $out = [];
        foreach ($ports as $mac => $p) {
            $ifIdx = $portIf[$p] ?? null;
            $out[] = [
                'mac'  => $mac,
                'port' => ($ifIdx !== null && isset($names[$ifIdx]))
                          ? $names[$ifIdx] : 'port ' . $p,
            ];
        }
        return $out;
    }

    /**
     * ARP / neighbour table: IP -> MAC (+ local interface).
     * Reads ipNetToMediaTable and ipNetToPhysicalTable.
     * @return array<string, array{mac:string,port:?string}> ip => info
     */
    public static function arp(string $host, array $cred): array
    {
        $s = self::session($host, $cred);
        if (!$s) {
            return [];
        }
        $names = self::ifNames($s);
        $out = [];

        // ipNetToMediaPhysAddress.<ifIndex>.<ip>: value is the MAC
        foreach (self::walk($s, self::OID_ARP_PHYSADDR) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_ARP_PHYSADDR);
            if (count($tail) < 5) {
                continue;
            }
            $ip = implode('.', array_slice($tail, -4));
            $mac = self::normaliseMac((string)$v);
            if ($mac !== null && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $out[$ip] = [
                    'mac'  => $mac,
                    'port' => isset($names[(int)$tail[0]]) ? $names[(int)$tail[0]] : null,
                ];
            }
        }

        // ipNetToPhysicalPhysAddress.<ifIndex>.<type>.<len>.<bytes>
        foreach (self::walk($s, self::OID_NTPPHYSADDR) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_NTPPHYSADDR);
            if (count($tail) < 4) {
                continue;
            }
            [$ifIdx, $type, $len] = [$tail[0], $tail[1], $tail[2]];
            $bytes = array_slice($tail, 3, $len);
            if (count($bytes) !== $len) {
                continue;
            }
            $ip = $type === 1 && $len === 4
                ? implode('.', $bytes)
                : ($type === 2 && $len === 16
                    ? (@inet_ntop(pack('C*', ...$bytes)) ?: null) : null);
            $mac = self::normaliseMac((string)$v);
            if ($ip !== null && $mac !== null && filter_var($ip, FILTER_VALIDATE_IP)) {
                $out[$ip] ??= [
                    'mac'  => $mac,
                    'port' => $names[$ifIdx] ?? null,
                ];
            }
        }
        $s->close();
        return $out;
    }

    /** ifIndex => interface name (ifName, falling back to ifDescr). */
    private static function ifNames(\SNMP $s): array
    {
        $names = [];
        foreach (self::walk($s, self::OID_IF_NAME) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_IF_NAME);
            if ($tail) {
                $names[(int)end($tail)] = trim((string)$v) ?: null;
            }
        }
        foreach (self::walk($s, self::OID_IF_DESCR) as $oid => $v) {
            $tail = self::oidTail($oid, self::OID_IF_DESCR);
            if ($tail) {
                $i = (int)end($tail);
                $names[$i] ??= trim((string)$v) ?: null;
            }
        }
        return array_filter($names);
    }

    /** Numeric OID suffix after $base as int list. */
    private static function oidTail(string $oid, string $base): array
    {
        $suffix = self::indexSuffix($oid, $base);
        $suffix = trim($suffix, '.');
        if ($suffix === '') {
            return [];
        }
        $parts = [];
        foreach (explode('.', $suffix) as $p) {
            if (!is_numeric($p)) {
                return [];
            }
            $parts[] = (int)$p;
        }
        return $parts;
    }

    /** @param int[] $bytes */
    private static function macFromOid(array $bytes): ?string
    {
        if (count($bytes) !== 6) {
            return null;
        }
        foreach ($bytes as $b) {
            if ($b < 0 || $b > 255) {
                return null;
            }
        }
        return strtolower(sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...$bytes));
    }

    private static function isMulticastMac(string $mac): bool
    {
        $first = hexdec(substr($mac, 0, 2));
        return $mac === 'ff:ff:ff:ff:ff:ff' || ($first & 0x01) === 0x01;
    }

    // ---------------- helpers ----------------

    private static function get(\SNMP $s, string $oid): ?string
    {
        $v = @$s->get($oid);
        return ($v === false || $v === null) ? null : (string)$v;
    }

    /** @return array<string,string> oid => value */
    private static function walk(\SNMP $s, string $oid): array
    {
        $r = @$s->walk($oid);
        return is_array($r) ? $r : [];
    }

    private static function indexSuffix(string $oid, string $base): string
    {
        $oid  = '.' . ltrim($oid, '.');
        $base = '.' . ltrim($base, '.');
        return str_starts_with($oid, $base) ? substr($oid, strlen($base)) : $oid;
    }

    /** @param array<string,string> $rows */
    private static function pickSuffix(array $rows, string $suffix): ?string
    {
        foreach ($rows as $oid => $val) {
            if (str_ends_with('.' . ltrim($oid, '.'), $suffix)) {
                $v = trim((string)$val);
                return $v !== '' ? $v : null;
            }
        }
        return null;
    }

    /** Suffix lookup that preserves binary values (no trimming). */
    private static function pickSuffixRaw(array $rows, string $suffix): ?string
    {
        foreach ($rows as $oid => $val) {
            if (str_ends_with('.' . ltrim($oid, '.'), $suffix)) {
                return (string)$val;
            }
        }
        return null;
    }

    /** @param array<string,string> $rows */
    private static function matchBySuffix(array $rows, string $suffix): ?string
    {
        foreach ($rows as $oid => $val) {
            if (str_ends_with('.' . ltrim($oid, '.'), $suffix)) {
                $v = trim((string)$val);
                return $v !== '' ? $v : null;
            }
        }
        return null;
    }

    /**
     * Accepts every form SNMP agents return: raw 6-byte octet string,
     * "00 1B 44 11 3A B7", "00:1b:44:11:3a:b7" or "001b44113ab7".
     */
    public static function normaliseMac(string $raw): ?string
    {
        // raw binary octet string (SNMP_VALUE_PLAIN returns these unescaped)
        if (strlen($raw) === 6 && preg_match('/[^\x20-\x7e]/', $raw)) {
            return implode(':', str_split(strtolower(bin2hex($raw)), 2));
        }
        $hex = strtolower(preg_replace('/[^0-9a-f]/i', '', $raw) ?? '');
        if (strlen($hex) === 12) {
            return implode(':', str_split($hex, 2));
        }
        // last resort: some agents send 6 printable-but-binary bytes
        if (strlen($raw) === 6) {
            return implode(':', str_split(strtolower(bin2hex($raw)), 2));
        }
        return null;
    }

    /**
     * CDP cacheAddress is a 4-byte IPv4 value, delivered either as a raw
     * octet string or as hex text depending on the agent.
     */
    public static function hexToIp(?string $raw): ?string
    {
        if ($raw === null || $raw === '') {
            return null;
        }
        if (strlen($raw) === 4) {
            $ip = implode('.', array_map('ord', str_split($raw)));
            return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
        }
        $hex = preg_replace('/[^0-9a-f]/i', '', $raw) ?? '';
        if (strlen($hex) !== 8) {
            return null;
        }
        $ip = implode('.', array_map(static fn($h) => hexdec($h), str_split($hex, 2)));
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
    }

    /**
     * Best-effort OS / version extraction from sysDescr.
     * @return array{0:?string,1:?string}
     */
    public static function parseSysDescr(string $d): array
    {
        $d = trim($d);
        if ($d === '') {
            return [null, null];
        }
        $patterns = [
            // Cisco IOS / IOS-XE
            '/Cisco IOS Software.*?Version\s+([^\s,]+)/i'          => 'Cisco IOS',
            '/Cisco Internetwork Operating System.*Version\s+([^\s,]+)/i' => 'Cisco IOS',
            '/Cisco NX-OS.*?Version\s+([^\s,]+)/i'                 => 'Cisco NX-OS',
            '/Cisco Adaptive Security Appliance Version\s+([^\s,]+)/i' => 'Cisco ASA',
            '/Arista Networks EOS version\s+([^\s,]+)/i'           => 'Arista EOS',
            '/JUNOS\s+([^\s,]+)/i'                                 => 'Juniper JUNOS',
            '/RouterOS\s+(?:\S+\s+)*?v?([0-9][0-9.]*[0-9a-z]*)/i'   => 'MikroTik RouterOS',
            '/FortiGate.*?v([0-9][^\s,]*)/i'                       => 'FortiOS',
            '/PAN-OS\s+([^\s,]+)/i'                                => 'PAN-OS',
            '/HP Comware.*?Version\s+([^\s,]+)/i'                  => 'HP Comware',
            '/ProCurve.*?revision\s+([^\s,]+)/i'                   => 'HP ProCurve',
            '/ArubaOS.*?Version\s+([^\s,]+)/i'                     => 'ArubaOS',
            '/Ubuntu\s+([0-9][^\s,]*)/i'                           => 'Ubuntu',
            '/Debian\s+([0-9][^\s,]*)/i'                           => 'Debian',
            '/Windows.*?Version\s+([^\s,]+)/i'                     => 'Windows',
        ];
        foreach ($patterns as $re => $os) {
            if (preg_match($re, $d, $m)) {
                return [$os, rtrim($m[1], '.,')];
            }
        }
        // Generic Linux: "Linux host 5.15.0-91-generic ..."
        if (preg_match('/^Linux\s+\S+\s+(\S+)/i', $d, $m)) {
            return ['Linux', $m[1]];
        }
        return [self::truncate($d, 120), null];
    }

    public static function truncate(?string $s, int $len = 255): ?string
    {
        if ($s === null) {
            return null;
        }
        $s = trim(preg_replace('/\s+/', ' ', $s) ?? '');
        return $s === '' ? null : substr($s, 0, $len);
    }
}
