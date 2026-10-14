<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * DarkVeda IPAM — file uploads (rack equipment photos, documentation).
 *
 * Files are stored under public/uploads/<bucket>/ with generated names, so a
 * user-supplied filename can never influence the path on disk. The original
 * name is kept in the database for display and download only.
 *
 * Security notes:
 *  - the extension is derived from the detected MIME type, not from the
 *    uploaded name, so "invoice.php" cannot land as a .php file;
 *  - SVG can carry scripts, so SVG (and every document) is served through
 *    the download endpoint with Content-Disposition: attachment and a
 *    restrictive CSP rather than being linked directly;
 *  - public/uploads ships with .htaccess and a note for nginx users to make
 *    sure the directory is never executed as PHP.
 */
final class Uploads
{
    public const MAX_IMAGE_BYTES = 8  * 1024 * 1024;   // 8 MB
    public const MAX_DOC_BYTES   = 32 * 1024 * 1024;   // 32 MB

    /** MIME => extension for equipment photos. */
    public const IMAGE_TYPES = [
        'image/png'     => 'png',
        'image/jpeg'    => 'jpg',
        'image/svg+xml' => 'svg',
        'image/webp'    => 'webp',
    ];

    /** MIME => extension for documentation. */
    public const DOC_TYPES = [
        'application/pdf' => 'pdf',
        'image/png'       => 'png',
        'image/jpeg'      => 'jpg',
        'image/svg+xml'   => 'svg',
        'image/webp'      => 'webp',
        'image/gif'       => 'gif',
        'text/plain'      => 'txt',
        'application/msword' => 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
        'application/zip' => 'zip',
    ];

    public const CATEGORIES = ['document', 'manual', 'diagram', 'photo', 'license', 'contract'];

    public static function baseDir(): string
    {
        return dirname(__DIR__) . '/public/uploads';
    }

    /** Create the bucket directory (and its guards) if needed. */
    public static function ensureDir(string $bucket): string
    {
        $base = self::baseDir();
        $dir  = $base . '/' . preg_replace('/[^a-z0-9_-]/i', '', $bucket);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException(self::writeFailureReason($dir));
        }
        $ht = $base . '/.htaccess';
        if (!file_exists($ht)) {
            @file_put_contents($ht, "php_flag engine off\nOptions -ExecCGI -Indexes\nAddType text/plain .php .phtml .php3 .php4 .php5 .php7 .php8\n");
        }
        return $dir;
    }

    public static function writable(): bool
    {
        $base = self::baseDir();
        if (!is_dir($base)) {
            return @mkdir($base, 0775, true) || is_dir($base);
        }
        return is_writable($base);
    }

    /**
     * Validate and store one uploaded file.
     *
     * @param array $file   entry from $_FILES
     * @param string $bucket subdirectory under public/uploads
     * @param array<string,string> $allowed MIME => extension
     * @return array{stored_path:string,filename:string,mime:string,size:int}
     * @throws \RuntimeException on any validation failure
     */
    public static function store(array $file, string $bucket, array $allowed, int $maxBytes): array
    {
        $err = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($err !== UPLOAD_ERR_OK) {
            throw new \RuntimeException(self::errorMessage($err));
        }
        $tmp = (string)($file['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            throw new \RuntimeException('Upload failed — no file received.');
        }
        $size = (int)($file['size'] ?? 0);
        if ($size <= 0) {
            throw new \RuntimeException('The uploaded file is empty.');
        }
        if ($size > $maxBytes) {
            throw new \RuntimeException(sprintf(
                'File is %s; the limit is %s.',
                self::human($size), self::human($maxBytes)
            ));
        }

        $mime = self::detectMime($tmp);
        if (!isset($allowed[$mime])) {
            throw new \RuntimeException('Unsupported file type (' . $mime . '). Allowed: '
                . implode(', ', array_values(array_unique($allowed))) . '.');
        }
        if ($mime === 'image/svg+xml') {
            self::assertSafeSvg($tmp);
        }

        $dir  = self::ensureDir($bucket);
        $name = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
        $dest = $dir . '/' . $name;

        // resolve every value that could fail *before* touching the filesystem,
        // so a later error can never leave an orphaned file behind
        $display = self::safeDisplayName((string)($file['name'] ?? $name));
        $stored  = 'uploads/' . basename($dir) . '/' . $name;

        if (!@move_uploaded_file($tmp, $dest)) {
            throw new \RuntimeException(self::writeFailureReason($dir));
        }
        @chmod($dest, 0644);

        return [
            'stored_path' => $stored,
            'filename'    => $display,
            'mime'        => $mime,
            'size'        => $size,
        ];
    }


    /** Explain precisely why a directory could not be written to. */
    public static function writeFailureReason(string $dir): string
    {
        $user = function_exists('posix_geteuid') && function_exists('posix_getpwuid')
            ? (posix_getpwuid(posix_geteuid())['name'] ?? 'the web server user')
            : 'the web server user';
        $parent = dirname($dir);

        if (!is_dir($dir)) {
            return sprintf('%s does not exist and could not be created. Run: mkdir -p %s && chown -R %s %s',
                $dir, $dir, $user, $parent);
        }
        if (!is_writable($dir)) {
            $owner = 'unknown';
            if (function_exists('posix_getpwuid')) {
                $st = @stat($dir);
                $owner = $st ? (posix_getpwuid($st['uid'])['name'] ?? (string)$st['uid']) : 'unknown';
            }
            return sprintf('%s is not writable by %s (owned by %s, mode %s). '
                . 'Fix it with: chown -R %s %s && chmod -R 775 %s',
                $dir, $user, $owner, substr(sprintf('%o', @fileperms($dir) ?: 0), -4), $user, $parent, $parent);
        }
        return sprintf('Writing to %s failed even though it appears writable. '
            . 'Check for a read-only mount, a full disk, or SELinux/AppArmor.', $dir);
    }

    public static function delete(?string $storedPath): void
    {
        if (!$storedPath) {
            return;
        }
        // stored_path is always "uploads/<bucket>/<generated>" — refuse anything else
        if (!preg_match('#^uploads/[a-z0-9_-]+/[a-f0-9]{32}\.[a-z0-9]{2,5}$#i', $storedPath)) {
            return;
        }
        $full = dirname(__DIR__) . '/public/' . $storedPath;
        if (is_file($full)) {
            @unlink($full);
        }
    }

    public static function absolutePath(string $storedPath): ?string
    {
        if (!preg_match('#^uploads/[a-z0-9_-]+/[a-f0-9]{32}\.[a-z0-9]{2,5}$#i', $storedPath)) {
            return null;
        }
        $full = dirname(__DIR__) . '/public/' . $storedPath;
        return is_file($full) ? $full : null;
    }

    public static function detectMime(string $path): string
    {
        if (function_exists('finfo_open')) {
            $fi = finfo_open(FILEINFO_MIME_TYPE);
            if ($fi) {
                $m = finfo_file($fi, $path);
                finfo_close($fi);
                if (is_string($m) && $m !== '') {
                    return $m;
                }
            }
        }
        if (function_exists('mime_content_type')) {
            $m = @mime_content_type($path);
            if (is_string($m) && $m !== '') {
                return $m;
            }
        }
        return 'application/octet-stream';
    }

    /** Reject SVGs carrying scripts or external references. */
    private static function assertSafeSvg(string $path): void
    {
        $head = (string)@file_get_contents($path, false, null, 0, 512 * 1024);
        if (preg_match('/<\s*script|javascript:|on[a-z]+\s*=|<\s*foreignObject|<!ENTITY/i', $head)) {
            throw new \RuntimeException('That SVG contains scripts or entities and was rejected. Export a plain SVG, or upload a PNG instead.');
        }
    }

    public static function safeDisplayName(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = preg_replace('/[\x00-\x1f\x7f]/', '', $name) ?? $name;
        // mbstring is not present in every PHP build, so truncate without it
        if (strlen($name) > 200) {
            $name = function_exists('mb_substr')
                ? mb_substr($name, 0, 200)
                : substr($name, 0, 200);
        }
        return $name !== '' ? $name : 'file';
    }

    public static function human(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        $v = (float)$bytes;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return ($i === 0 ? (string)(int)$v : number_format($v, 1)) . ' ' . $units[$i];
    }

    private static function errorMessage(int $code): string
    {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE =>
                'File is larger than the PHP upload limit (upload_max_filesize / post_max_size).',
            UPLOAD_ERR_PARTIAL   => 'The upload was interrupted — please try again.',
            UPLOAD_ERR_NO_FILE   => 'No file was selected.',
            UPLOAD_ERR_NO_TMP_DIR=> 'PHP has no temporary directory configured.',
            UPLOAD_ERR_CANT_WRITE=> 'PHP could not write the file to disk.',
            UPLOAD_ERR_EXTENSION => 'A PHP extension blocked the upload.',
            default              => 'Upload failed (error code ' . $code . ').',
        };
    }

    /** Icon class for a stored file, used across the documentation UI. */
    public static function icon(?string $mime): string
    {
        return match (true) {
            $mime === 'application/pdf'            => 'bi-file-earmark-pdf',
            str_starts_with((string)$mime, 'image/') => 'bi-file-earmark-image',
            str_contains((string)$mime, 'word')    => 'bi-file-earmark-word',
            str_contains((string)$mime, 'sheet'),
            str_contains((string)$mime, 'excel')   => 'bi-file-earmark-spreadsheet',
            str_contains((string)$mime, 'zip')     => 'bi-file-earmark-zip',
            default                                 => 'bi-file-earmark-text',
        };
    }
}
