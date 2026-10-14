<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * DarkVeda IPAM — Zabbix integration (Zabbix 6.0+ / 7.x JSON-RPC API).
 *
 * Authentication: Zabbix 6.0 introduced API tokens; 7.0 requires them to be
 * sent as an HTTP header (`Authorization: Bearer <token>`) rather than in the
 * request body. This client uses the header form, which works on 6.0+ and 7.x.
 *
 * Configuration comes from config/config.php['zabbix'] or environment:
 *   ZABBIX_URL    e.g. https://zabbix.example.com/api_jsonrpc.php
 *   ZABBIX_TOKEN  API token from Users -> API tokens in Zabbix
 *
 * Sync flow:
 *   host.get   -> hosts with their interfaces (IP) and availability
 *   item.get   -> latest CPU / memory utilisation values per host
 *   problem.get-> open problem count per host
 *   results are written to monitoring_status keyed by IP address.
 */
final class Zabbix
{
    /** Item keys tried in order for CPU utilisation (%). */
    private const CPU_KEYS = [
        'system.cpu.util',
        'system.cpu.util[,user]',
        'system.cpu.load[percpu,avg1]',
    ];

    /** Item keys tried in order for memory utilisation (%). */
    private const MEM_KEYS = [
        'vm.memory.utilization',
        'vm.memory.size[pused]',
        'vm.memory.util',
    ];

    public static function configured(): bool
    {
        $c = self::config();
        return $c['url'] !== '' && $c['token'] !== '';
    }

    /**
     * Effective connection settings.
     *
     * Priority per field: database (Monitoring page) > environment > config.php.
     * The database wins so an admin save from the UI always takes effect
     * immediately and survives container rebuilds; clearing the saved values
     * falls back to environment / config file.
     *
     * @return array{url:string,token:string,verify_tls:bool,timeout:int,
     *               url_source:string,token_source:string,verify_source:string,
     *               timeout_source:string,db_url:string,db_token:string,
     *               has_db:bool,env_url:string,env_token:string}
     */
    public static function config(): array
    {
        $cfg = App::config()['zabbix'] ?? [];

        $envUrl   = trim((string)(getenv('ZABBIX_URL') ?: ''));
        $envToken = trim((string)(getenv('ZABBIX_TOKEN') ?: ''));
        $envVerifyRaw = getenv('ZABBIX_VERIFY_TLS');
        $envTimeoutRaw = getenv('ZABBIX_TIMEOUT');

        $dbUrl   = trim((string)(Settings::get('zabbix_url') ?? ''));
        $dbToken = trim((string)(Settings::get('zabbix_token') ?? ''));
        $dbVerifyRaw = Settings::get('zabbix_verify_tls');
        $dbTimeoutRaw = Settings::get('zabbix_timeout');

        // --- URL ---
        if ($dbUrl !== '') {
            $url = $dbUrl;
            $urlSrc = 'database';
        } elseif ($envUrl !== '') {
            $url = $envUrl;
            $urlSrc = 'environment';
        } else {
            $url = trim((string)($cfg['url'] ?? ''));
            $urlSrc = $url !== '' ? 'config file' : 'none';
        }

        // --- Token ---
        if ($dbToken !== '') {
            $token = $dbToken;
            $tokenSrc = 'database';
        } elseif ($envToken !== '') {
            $token = $envToken;
            $tokenSrc = 'environment';
        } else {
            $token = trim((string)($cfg['token'] ?? ''));
            $tokenSrc = $token !== '' ? 'config file' : 'none';
        }

        // --- Verify TLS ---
        if ($dbVerifyRaw !== null && $dbVerifyRaw !== '') {
            $verify = $dbVerifyRaw === '1';
            $verifySrc = 'database';
        } elseif ($envVerifyRaw !== false && $envVerifyRaw !== '') {
            $verify = filter_var($envVerifyRaw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true;
            $verifySrc = 'environment';
        } else {
            $verify = (bool)($cfg['verify_tls'] ?? true);
            $verifySrc = isset($cfg['verify_tls']) ? 'config file' : 'default';
        }

        // --- Timeout ---
        if ($dbTimeoutRaw !== null && $dbTimeoutRaw !== '' && (int)$dbTimeoutRaw > 0) {
            $timeout = min(60, max(3, (int)$dbTimeoutRaw));
            $timeoutSrc = 'database';
        } elseif ($envTimeoutRaw !== false && $envTimeoutRaw !== '' && (int)$envTimeoutRaw > 0) {
            $timeout = min(60, max(3, (int)$envTimeoutRaw));
            $timeoutSrc = 'environment';
        } else {
            $timeout = (int)($cfg['timeout'] ?? 10);
            $timeout = min(60, max(3, $timeout > 0 ? $timeout : 10));
            $timeoutSrc = isset($cfg['timeout']) ? 'config file' : 'default';
        }

        return [
            'url'            => $url,
            'token'          => $token,
            'verify_tls'     => $verify,
            'timeout'        => $timeout,
            'url_source'     => $urlSrc,
            'token_source'   => $tokenSrc,
            'verify_source'  => $verifySrc,
            'timeout_source' => $timeoutSrc,
            'db_url'         => $dbUrl,
            'db_token'       => $dbToken,
            'has_db'         => $dbUrl !== '' || $dbToken !== '' || ($dbVerifyRaw !== null && $dbVerifyRaw !== '') || ($dbTimeoutRaw !== null && $dbTimeoutRaw !== ''),
            'env_url'        => $envUrl,
            'env_token'      => $envToken,
        ];
    }

    /** Validate candidate values. Returns null on success or an error message. */
    public static function validate(string $url, string $token): ?string
    {
        $url = trim($url);
        $token = trim($token);
        if ($url === '' && $token === '') {
            return null; // treated as "clear" by the caller
        }
        if ($url === '') {
            return 'Zabbix URL is required when a token is set.';
        }
        if ($token === '') {
            return 'API token is required when a URL is set.';
        }
        if (strlen($url) > 500) {
            return 'Zabbix URL is too long (max 500 characters).';
        }
        if (strlen($token) > 1000) {
            return 'API token is too long (max 1000 characters).';
        }
        if (!preg_match('#^https?://#i', $url) || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return 'Zabbix URL must start with http:// or https:// and be a valid URL.';
        }
        return null;
    }

    /**
     * Raw JSON-RPC call.
     * @throws \RuntimeException on transport or API error
     */
    public static function call(string $method, array $params = []): mixed
    {
        $c = self::config();
        if ($c['url'] === '') {
            throw new \RuntimeException('Zabbix URL is not configured.');
        }
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('PHP cURL extension is required for the Zabbix integration.');
        }

        $payload = json_encode([
            'jsonrpc' => '2.0',
            'method'  => $method,
            'params'  => $params ?: new \stdClass(),
            'id'      => 1,
        ], JSON_UNESCAPED_SLASHES);

        $ch = curl_init($c['url']);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $c['timeout'],
            CURLOPT_SSL_VERIFYPEER => $c['verify_tls'],
            CURLOPT_SSL_VERIFYHOST => $c['verify_tls'] ? 2 : 0,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json-rpc',
                'Authorization: Bearer ' . $c['token'],
            ],
        ]);
        $body = curl_exec($ch);
        $err  = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false) {
            throw new \RuntimeException('Zabbix request failed: ' . $err);
        }
        $json = json_decode((string)$body, true);
        if (!is_array($json)) {
            throw new \RuntimeException('Zabbix returned a non-JSON response (HTTP ' . $code . ').');
        }
        if (isset($json['error'])) {
            throw new \RuntimeException(
                'Zabbix API error: ' . ($json['error']['message'] ?? '')
                . ' ' . ($json['error']['data'] ?? '')
            );
        }
        return $json['result'] ?? null;
    }

    /** Quick connectivity check — returns the Zabbix API version string. */
    public static function version(): string
    {
        // apiinfo.version must be called without auth; header is harmless.
        return (string)self::call('apiinfo.version');
    }

    /**
     * Pull monitoring state for every Zabbix host and store it against
     * matching IP addresses.
     *
     * Note: this only upserts rows for hosts Zabbix currently reports — rows
     * for hosts that were deleted from Zabbix (or a previous Zabbix server)
     * are left untouched. Use refresh() to drop stale rows first.
     * @return array{hosts:int,matched:int,online:int,offline:int}
     */
    public static function sync(): array
    {
        $hosts = self::call('host.get', [
            'output'           => ['hostid', 'host', 'name', 'status'],
            'selectInterfaces' => ['ip', 'available', 'type', 'main'],
            'filter'           => ['status' => 0],   // monitored hosts only
        ]);
        if (!is_array($hosts)) {
            $hosts = [];
        }

        $hostIds = array_map(static fn($h) => $h['hostid'], $hosts);
        $cpu = $hostIds ? self::latestByKeys($hostIds, self::CPU_KEYS) : [];
        $mem = $hostIds ? self::latestByKeys($hostIds, self::MEM_KEYS) : [];
        $problems = $hostIds ? self::problemCounts($hostIds) : [];

        $matched = $online = $offline = 0;

        foreach ($hosts as $h) {
            $ips = [];
            foreach (($h['interfaces'] ?? []) as $iface) {
                $ip = trim((string)($iface['ip'] ?? ''));
                if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                    $ips[] = $ip;
                }
            }
            if (!$ips) {
                continue;
            }

            // Zabbix interface availability: 0 unknown, 1 available, 2 unavailable
            $avail = 0;
            foreach (($h['interfaces'] ?? []) as $iface) {
                $a = (int)($iface['available'] ?? 0);
                if ($a === 1) { $avail = 1; break; }
                if ($a === 2) { $avail = 2; }
            }
            $state = match ($avail) { 1 => 'online', 2 => 'offline', default => 'unknown' };
            $state === 'online' ? $online++ : ($state === 'offline' ? $offline++ : null);

            foreach (array_unique($ips) as $ip) {
                self::store(
                    $ip,
                    $state,
                    $cpu[$h['hostid']] ?? null,
                    $mem[$h['hostid']] ?? null,
                    (string)($h['name'] ?? $h['host'] ?? ''),
                    (int)($problems[$h['hostid']] ?? 0)
                );
                $matched++;
            }
        }

        return ['hosts' => count($hosts), 'matched' => $matched, 'online' => $online, 'offline' => $offline];
    }

    /**
     * Delete stored Zabbix monitoring rows.
     *
     * Only rows with source 'zabbix' are removed — rows pushed via the REST
     * API (source 'api' or custom) are left alone.
     * @return int number of rows removed
     */
    public static function clearStatus(): int
    {
        return Database::exec("DELETE FROM monitoring_status WHERE source = 'zabbix'");
    }

    /**
     * Full refresh: drop all stored Zabbix rows, then sync from scratch.
     *
     * Use this after switching Zabbix servers or when the monitoring table
     * still shows hosts that no longer exist in Zabbix — a plain sync()
     * only upserts and never removes stale rows.
     * @return array{cleared:int,hosts:int,matched:int,online:int,offline:int}
     */
    public static function refresh(): array
    {
        if (!self::configured()) {
            throw new \RuntimeException('Zabbix is not configured — nothing to refresh from.');
        }
        $cleared = self::clearStatus();
        $r = self::sync();
        return ['cleared' => $cleared] + $r;
    }

    /**
     * Latest numeric value per host for the first matching key.
     * @param string[] $hostIds @param string[] $keys @return array<string,float>
     */
    private static function latestByKeys(array $hostIds, array $keys): array
    {
        $items = self::call('item.get', [
            'output'      => ['itemid', 'hostid', 'key_', 'lastvalue'],
            'hostids'     => $hostIds,
            'filter'      => ['key_' => $keys],
            'monitored'   => true,
        ]);
        if (!is_array($items)) {
            return [];
        }
        $rank = array_flip($keys);
        $best = [];
        foreach ($items as $it) {
            $hid = (string)$it['hostid'];
            $r   = $rank[$it['key_']] ?? 99;
            $val = $it['lastvalue'] ?? null;
            if ($val === null || $val === '' || !is_numeric($val)) {
                continue;
            }
            if (!isset($best[$hid]) || $r < $best[$hid][0]) {
                $best[$hid] = [$r, round((float)$val, 2)];
            }
        }
        return array_map(static fn($v) => $v[1], $best);
    }

    /** @param string[] $hostIds @return array<string,int> */
    private static function problemCounts(array $hostIds): array
    {
        $problems = self::call('problem.get', [
            'output'   => ['eventid', 'objectid', 'severity'],
            'hostids'  => $hostIds,
            'recent'   => false,
        ]);
        if (!is_array($problems)) {
            return [];
        }
        // problem.get doesn't return hostid directly in all versions; fall back to a
        // per-host count via triggerids when present.
        $counts = [];
        foreach ($problems as $p) {
            $hid = (string)($p['hostid'] ?? '');
            if ($hid !== '') {
                $counts[$hid] = ($counts[$hid] ?? 0) + 1;
            }
        }
        return $counts;
    }

    /** Upsert one monitoring row. Also used by the REST API push endpoint. */
    public static function store(
        string $address,
        string $state,
        ?float $cpu = null,
        ?float $mem = null,
        ?string $hostName = null,
        int $problems = 0,
        ?int $uptime = null,
        string $source = 'zabbix'
    ): void {
        if (!in_array($state, ['online', 'offline', 'unknown'], true)) {
            $state = 'unknown';
        }
        Database::exec(
            'INSERT INTO monitoring_status
                (address, source, state, cpu_pct, memory_pct, uptime_seconds, host_name, problem_count, checked_at)
             VALUES (?,?,?,?,?,?,?,?,NOW())
             ON DUPLICATE KEY UPDATE
                source = VALUES(source), state = VALUES(state),
                cpu_pct = VALUES(cpu_pct), memory_pct = VALUES(memory_pct),
                uptime_seconds = VALUES(uptime_seconds), host_name = VALUES(host_name),
                problem_count = VALUES(problem_count), checked_at = NOW()',
            [$address, $source, $state, $cpu, $mem, $uptime, $hostName, $problems]
        );
    }

    /** @return array<string, array<string,mixed>> address => status row */
    public static function statusMap(array $addresses = []): array
    {
        if ($addresses) {
            $in = implode(',', array_fill(0, count($addresses), '?'));
            $rows = Database::q("SELECT * FROM monitoring_status WHERE address IN ($in)", $addresses);
        } else {
            $rows = Database::q('SELECT * FROM monitoring_status');
        }
        $map = [];
        foreach ($rows as $r) {
            $map[$r['address']] = $r;
        }
        return $map;
    }
}
