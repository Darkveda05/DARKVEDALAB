<?php
declare(strict_types=1);

namespace DarkVeda;

use PDOException;

/**
 * DarkVeda IPAM — key/value application settings.
 *
 * Values live in `app_settings` so they survive container rebuilds and are
 * shared across every session, unlike browser storage.
 */
final class Settings
{
    /** @var array<string,?string>|null */
    private static ?array $cache = null;

    public static function all(): array
    {
        if (self::$cache === null) {
            self::$cache = [];
            try {
                foreach (Database::q('SELECT skey, sval FROM app_settings') as $r) {
                    self::$cache[$r['skey']] = $r['sval'];
                }
            } catch (PDOException) {
                // table missing (pre-3.0 database) — behave as if empty
                self::$cache = [];
            }
        }
        return self::$cache;
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        $all = self::all();
        return array_key_exists($key, $all) && $all[$key] !== null ? $all[$key] : $default;
    }

    public static function int(string $key, int $default = 0): int
    {
        $v = self::get($key);
        return $v === null || $v === '' ? $default : (int)$v;
    }

    public static function set(string $key, ?string $value): void
    {
        Database::exec(
            'INSERT INTO app_settings (skey, sval) VALUES (?,?)
             ON DUPLICATE KEY UPDATE sval = VALUES(sval)',
            [$key, $value]
        );
        self::$cache[$key] = $value;
    }

    public static function delete(string ...$keys): void
    {
        foreach ($keys as $key) {
            Database::exec('DELETE FROM app_settings WHERE skey = ?', [$key]);
            if (self::$cache !== null) {
                unset(self::$cache[$key]);
            }
        }
    }
}
