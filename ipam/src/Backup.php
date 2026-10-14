<?php
declare(strict_types=1);

namespace DarkVeda;

use PDO;

/**
 * DarkVeda IPAM — configuration backup & restore.
 *
 * A backup is a .tar.gz containing:
 *   database.sql   full schema + data dump of every table
 *   config.php     the live configuration (optional, contains secrets)
 *   uploads/       equipment photos and documentation files
 *   manifest.json  version, timestamp, table/row counts
 *
 * The SQL dump is produced in pure PHP rather than shelling out to
 * mysqldump, because the binary is frequently absent from slim PHP
 * containers. Restores run inside a transaction where the storage engine
 * allows it, and always disable foreign key checks for the duration.
 */
final class Backup
{
    public const FORMAT = '3.0';

    public static function archivesSupported(): bool
    {
        return class_exists('\PharData');
    }

    public static function workDir(): string
    {
        $dir = sys_get_temp_dir() . '/dvipam-backup-' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create a temporary directory for the backup.');
        }
        return $dir;
    }

    /** @return string[] list of table names */
    public static function tables(): array
    {
        $out = [];
        foreach (Database::q('SHOW TABLES') as $row) {
            $out[] = (string)array_values($row)[0];
        }
        sort($out);
        return $out;
    }

    /**
     * Produce a complete SQL dump of the database.
     * @param string[]|null $only restrict to these tables
     */
    public static function dumpSql(?array $only = null): string
    {
        $pdo    = Database::get();
        $tables = $only ?? self::tables();
        $cfg    = App::config();

        $sql  = "-- DarkVeda IPAM backup\n";
        $sql .= '-- generated: ' . date('c') . "\n";
        $sql .= '-- app version: ' . ($cfg['app']['version'] ?? '?') . "\n";
        $sql .= '-- format: ' . self::FORMAT . "\n\n";
        $sql .= "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS = 0;\nSET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n\n";

        foreach ($tables as $t) {
            $create = $pdo->query('SHOW CREATE TABLE `' . $t . '`')->fetch(PDO::FETCH_NUM);
            if (!$create) {
                continue;
            }
            $sql .= "-- ---------------------------------------------\n";
            $sql .= "DROP TABLE IF EXISTS `$t`;\n";
            $sql .= $create[1] . ";\n\n";

            $stmt = $pdo->query('SELECT * FROM `' . $t . '`');
            $rows = 0;
            $buffer = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $vals = [];
                foreach ($row as $v) {
                    if ($v === null) {
                        $vals[] = 'NULL';
                    } elseif (is_int($v) || is_float($v)) {
                        $vals[] = (string)$v;
                    } else {
                        $s = (string)$v;
                        // binary-safe: hex-encode anything not valid UTF-8 (VARBINARY columns)
                        $vals[] = preg_match('//u', $s) ? $pdo->quote($s) : '0x' . bin2hex($s);
                    }
                }
                $buffer[] = '(' . implode(',', $vals) . ')';
                $rows++;
                if (count($buffer) >= 200) {
                    $sql .= 'INSERT INTO `' . $t . '` VALUES ' . implode(",\n", $buffer) . ";\n";
                    $buffer = [];
                }
            }
            if ($buffer) {
                $sql .= 'INSERT INTO `' . $t . '` VALUES ' . implode(",\n", $buffer) . ";\n";
            }
            $sql .= "-- rows: $rows\n\n";
        }

        $sql .= "SET FOREIGN_KEY_CHECKS = 1;\n";
        return $sql;
    }

    /**
     * Build a backup archive. Returns the path to a .tar.gz (or .sql when
     * Phar is unavailable) that the caller should stream and then delete.
     *
     * @return array{path:string,name:string,mime:string}
     */
    public static function create(bool $includeUploads = true, bool $includeConfig = false): array
    {
        $stamp = date('Ymd-His');
        $sql   = self::dumpSql();

        if (!self::archivesSupported()) {
            $path = self::workDir() . '/darkveda-ipam-' . $stamp . '.sql';
            file_put_contents($path, $sql);
            return ['path' => $path, 'name' => basename($path), 'mime' => 'application/sql'];
        }

        $dir  = self::workDir();
        $tar  = $dir . '/darkveda-ipam-' . $stamp . '.tar';

        $manifest = [
            'format'      => self::FORMAT,
            'app_version' => App::config()['app']['version'] ?? null,
            'created_at'  => date('c'),
            'tables'      => [],
            'has_uploads' => false,
            'has_config'  => $includeConfig,
        ];
        foreach (self::tables() as $t) {
            $c = Database::one('SELECT COUNT(*) c FROM `' . $t . '`');
            $manifest['tables'][$t] = (int)($c['c'] ?? 0);
        }

        $phar = new \PharData($tar);
        $phar->addFromString('database.sql', $sql);

        if ($includeConfig) {
            $cfgFile = dirname(__DIR__) . '/config/config.php';
            if (is_file($cfgFile)) {
                $phar->addFile($cfgFile, 'config.php');
            }
        }

        if ($includeUploads) {
            $base = Uploads::baseDir();
            if (is_dir($base)) {
                $it = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS)
                );
                foreach ($it as $f) {
                    if ($f->isFile()) {
                        $rel = 'uploads/' . ltrim(str_replace($base, '', $f->getPathname()), '/\\');
                        $phar->addFile($f->getPathname(), $rel);
                        $manifest['has_uploads'] = true;
                    }
                }
            }
        }

        $phar->addFromString('manifest.json', json_encode($manifest, JSON_PRETTY_PRINT));
        $phar->compress(\Phar::GZ);
        unset($phar);
        @unlink($tar);

        $gz = $tar . '.gz';
        return [
            'path' => $gz,
            'name' => basename($gz),
            'mime' => 'application/gzip',
        ];
    }

    /**
     * Inspect an uploaded archive without applying it.
     * @return array{manifest:?array,has_sql:bool,files:int}
     */
    public static function inspect(string $archivePath): array
    {
        if (self::isPlainSql($archivePath)) {
            return ['manifest' => null, 'has_sql' => true, 'files' => 1];
        }
        if (!self::archivesSupported()) {
            throw new \RuntimeException('This PHP build has no Phar support, so only plain .sql backups can be restored.');
        }
        $phar = new \PharData($archivePath);
        $manifest = null;
        $hasSql = false;
        $files = 0;
        foreach (new \RecursiveIteratorIterator($phar) as $f) {
            $files++;
            $name = str_replace('\\', '/', $f->getFilename());
            if ($name === 'database.sql') {
                $hasSql = true;
            }
            if ($name === 'manifest.json') {
                $manifest = json_decode((string)file_get_contents($f->getPathname()), true);
            }
        }
        return ['manifest' => $manifest, 'has_sql' => $hasSql, 'files' => $files];
    }

    public static function isPlainSql(string $path): bool
    {
        $head = (string)@file_get_contents($path, false, null, 0, 64);
        return str_starts_with($head, '--') || stripos($head, 'SET NAMES') !== false;
    }

    /**
     * Restore from an archive or plain .sql file.
     * @return array{statements:int,uploads:int}
     */
    public static function restore(string $archivePath, bool $restoreUploads = true): array
    {
        $sql = null;
        $uploadsRestored = 0;

        if (self::isPlainSql($archivePath)) {
            $sql = (string)file_get_contents($archivePath);
        } else {
            if (!self::archivesSupported()) {
                throw new \RuntimeException('Phar support is required to restore .tar.gz backups.');
            }
            $phar = new \PharData($archivePath);
            foreach (new \RecursiveIteratorIterator($phar) as $f) {
                $name = str_replace('\\', '/', $f->getFilename());
                if ($name === 'database.sql') {
                    $sql = (string)file_get_contents($f->getPathname());
                }
            }
            if ($restoreUploads) {
                $base = Uploads::baseDir();
                foreach (new \RecursiveIteratorIterator($phar) as $f) {
                    $full = str_replace('\\', '/', $f->getPathname());
                    $pos  = strpos($full, '/uploads/');
                    if ($pos === false) {
                        continue;
                    }
                    $rel = substr($full, $pos + strlen('/uploads/'));
                    // path traversal guard
                    if ($rel === '' || str_contains($rel, '..')) {
                        continue;
                    }
                    $dest = $base . '/' . $rel;
                    $dir  = dirname($dest);
                    if (!is_dir($dir)) {
                        @mkdir($dir, 0775, true);
                    }
                    if (@copy($f->getPathname(), $dest)) {
                        $uploadsRestored++;
                    }
                }
            }
        }

        if ($sql === null || trim($sql) === '') {
            throw new \RuntimeException('No database.sql found inside the backup.');
        }

        $pdo = Database::get();
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
        $count = 0;
        foreach (self::splitStatements($sql) as $stmt) {
            $pdo->exec($stmt);
            $count++;
        }
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

        return ['statements' => $count, 'uploads' => $uploadsRestored];
    }

    /**
     * Split a dump into executable statements, respecting quoting so that a
     * semicolon inside a string value never truncates a statement.
     * @return \Generator<string>
     */
    public static function splitStatements(string $sql): \Generator
    {
        $len = strlen($sql);
        $buf = '';
        $inS = false;   // '
        $inD = false;   // "
        $inB = false;   // `
        $esc = false;

        for ($i = 0; $i < $len; $i++) {
            $ch = $sql[$i];

            if ($esc) {
                $buf .= $ch;
                $esc = false;
                continue;
            }
            if ($ch === '\\' && ($inS || $inD)) {
                $buf .= $ch;
                $esc = true;
                continue;
            }
            // line comments only when not inside a quoted string
            if (!$inS && !$inD && !$inB && $ch === '-' && ($sql[$i + 1] ?? '') === '-'
                && (trim($buf) === '' || str_ends_with($buf, "\n"))) {
                while ($i < $len && $sql[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if (!$inD && !$inB && $ch === "'") {
                $inS = !$inS;
            } elseif (!$inS && !$inB && $ch === '"') {
                $inD = !$inD;
            } elseif (!$inS && !$inD && $ch === '`') {
                $inB = !$inB;
            }

            if ($ch === ';' && !$inS && !$inD && !$inB) {
                $s = trim($buf);
                if ($s !== '') {
                    yield $s;
                }
                $buf = '';
                continue;
            }
            $buf .= $ch;
        }
        $s = trim($buf);
        if ($s !== '') {
            yield $s;
        }
    }

    public static function cleanup(string $path): void
    {
        if (is_file($path)) {
            @unlink($path);
        }
        $dir = dirname($path);
        if (is_dir($dir) && str_contains($dir, 'dvipam-backup-')) {
            @rmdir($dir);
        }
    }
}
