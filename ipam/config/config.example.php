<?php
declare(strict_types=1);

/**
 * DarkVeda IPAM — configuration template.
 *
 * Copy this file to config/config.php and edit it, or leave it in place and
 * supply everything through environment variables (the Docker-friendly
 * route — every value below falls back to an env var first).
 *
 *   cp config/config.example.php config/config.php
 *
 * config/config.php is git-ignored on purpose: it holds credentials.
 */
return [
    'app' => [
        'name'     => 'DarkVeda IPAM',
        'version'  => '2.0',
        'debug'    => filter_var(getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOL),
        'timezone' => getenv('APP_TZ') ?: 'UTC',
    ],
    'db' => [
        'host'     => getenv('DB_HOST') ?: '127.0.0.1',
        'port'     => (int)(getenv('DB_PORT') ?: 3306),
        'name'     => getenv('DB_NAME') ?: 'darkveda_ipam',
        'user'     => getenv('DB_USER') ?: 'darkveda',
        'password' => getenv('DB_PASS') ?: '',
        'charset'  => 'utf8mb4',
    ],
    'zabbix' => [
        // Zabbix 6.0+ / 7.x, e.g. http://zabbix.example.com/zabbix/api_jsonrpc.php
        'url'        => getenv('ZABBIX_URL') ?: '',
        // Zabbix -> Users -> API tokens. A read-only user is strongly preferred.
        'token'      => getenv('ZABBIX_TOKEN') ?: '',
        'verify_tls' => filter_var(getenv('ZABBIX_VERIFY_TLS') ?: 'true', FILTER_VALIDATE_BOOL),
        'timeout'    => (int)(getenv('ZABBIX_TIMEOUT') ?: 10),
    ],
    'security' => [
        'session_name'     => 'dvipam_session',
        'session_lifetime' => 3600 * 8,
        'bcrypt_cost'      => 12,
    ],
];
