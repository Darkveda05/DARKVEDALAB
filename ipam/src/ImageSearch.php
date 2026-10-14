<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * DarkVeda IPAM — device model image lookup.
 *
 * Searches openly-licensed image sources for a hardware model (for example
 * "MikroTik RB5009UPr" or "Cisco C9200L") so a rack elevation can show the
 * real device instead of a blank panel.
 *
 * Source: Wikimedia Commons. It is deliberately the default because it needs
 * no API key and everything on it is freely licensed — most image search APIs
 * either require paid keys or return material that cannot legally be copied
 * onto your own server. Results still carry their attribution, which is
 * stored alongside the image.
 *
 * Nothing is downloaded until a person explicitly picks a result: search
 * returns candidates, `import()` saves the chosen one.
 */
final class ImageSearch
{
    private const ENDPOINT   = 'https://commons.wikimedia.org/w/api.php';
    private const UA         = 'DarkVedaIPAM/4.0 (self-hosted IPAM; device model images)';
    private const CACHE_HOURS = 168;   // one week
    private const MAX_BYTES   = 8 * 1024 * 1024;

    public static function enabled(): bool
    {
        return Settings::get('image_search_enabled', '1') === '1' && self::transportAvailable();
    }

    public static function transportAvailable(): bool
    {
        return function_exists('curl_init') || (bool)ini_get('allow_url_fopen');
    }

    /**
     * Search for candidate images.
     *
     * @return array<int, array{title:string,thumb:string,url:string,width:int,height:int,mime:string,credit:string,descriptionurl:string}>
     * @throws \RuntimeException when the lookup cannot be performed
     */
    public static function search(string $query, int $limit = 12, bool $useCache = true): array
    {
        $query = trim(preg_replace('/\s+/', ' ', $query) ?? '');
        if ($query === '') {
            throw new \RuntimeException('Enter a model to search for.');
        }
        if (!self::transportAvailable()) {
            throw new \RuntimeException('Neither cURL nor allow_url_fopen is available, so images cannot be fetched.');
        }

        if ($useCache) {
            $row = Database::one(
                'SELECT results FROM model_image_cache
                 WHERE query = ? AND fetched_at > NOW() - INTERVAL ? HOUR',
                [$query, self::CACHE_HOURS]
            );
            if ($row && $row['results']) {
                $cached = json_decode((string)$row['results'], true);
                if (is_array($cached)) {
                    return array_slice($cached, 0, $limit);
                }
            }
        }

        // One round trip: full-text search plus image metadata for each hit.
        $params = [
            'action'      => 'query',
            'format'      => 'json',
            'formatversion' => '2',
            'generator'   => 'search',
            'gsrsearch'   => 'filetype:bitmap ' . $query,
            'gsrnamespace' => '6',            // File:
            'gsrlimit'    => (string)max(1, min(30, $limit * 2)),
            'prop'        => 'imageinfo',
            'iiprop'      => 'url|size|mime|extmetadata',
            'iiurlwidth'  => '320',
        ];
        $json = self::httpGetJson(self::ENDPOINT . '?' . http_build_query($params));

        $out = [];
        foreach ($json['query']['pages'] ?? [] as $page) {
            $info = $page['imageinfo'][0] ?? null;
            if (!$info || empty($info['url'])) {
                continue;
            }
            $mime = (string)($info['mime'] ?? '');
            if (!isset(Uploads::IMAGE_TYPES[$mime])) {
                continue;
            }
            $meta   = $info['extmetadata'] ?? [];
            $artist = strip_tags((string)($meta['Artist']['value'] ?? ''));
            $lic    = (string)($meta['LicenseShortName']['value'] ?? '');
            $credit = trim(($artist !== '' ? $artist : 'Wikimedia Commons') . ($lic !== '' ? ' · ' . $lic : ''));

            $out[] = [
                'title'          => (string)($page['title'] ?? 'file'),
                'thumb'          => (string)($info['thumburl'] ?? $info['url']),
                'url'            => (string)$info['url'],
                'width'          => (int)($info['width'] ?? 0),
                'height'         => (int)($info['height'] ?? 0),
                'mime'           => $mime,
                'credit'         => Uploads::human((int)($info['size'] ?? 0)) . ' · ' . $credit,
                'descriptionurl' => (string)($info['descriptionurl'] ?? ''),
            ];
            if (count($out) >= $limit) {
                break;
            }
        }

        // Wide images are what rack elevations need; rank them first.
        usort($out, static function ($a, $b) {
            $ra = $a['height'] > 0 ? $a['width'] / $a['height'] : 0;
            $rb = $b['height'] > 0 ? $b['width'] / $b['height'] : 0;
            return $rb <=> $ra;
        });

        try {
            Database::exec(
                'INSERT INTO model_image_cache (query, results) VALUES (?,?)
                 ON DUPLICATE KEY UPDATE results = VALUES(results), fetched_at = NOW()',
                [$query, json_encode($out)]
            );
        } catch (\Throwable) {
            // caching is a nicety, never fatal
        }

        return $out;
    }

    /**
     * Download a chosen result into public/uploads and return its stored path.
     *
     * @return array{stored_path:string,mime:string,size:int}
     */
    public static function import(string $url, string $bucket = 'models'): array
    {
        if (!preg_match('#^https://upload\.wikimedia\.org/#i', $url)
            && !preg_match('#^https://commons\.wikimedia\.org/#i', $url)) {
            throw new \RuntimeException('Only images from the search results can be imported.');
        }

        $body = self::httpGetRaw($url, self::MAX_BYTES);
        if ($body === '' ) {
            throw new \RuntimeException('The image could not be downloaded.');
        }

        $tmp = tempnam(sys_get_temp_dir(), 'dvimg');
        file_put_contents($tmp, $body);
        $mime = Uploads::detectMime($tmp);

        if (!isset(Uploads::IMAGE_TYPES[$mime])) {
            @unlink($tmp);
            throw new \RuntimeException('Downloaded file is not a supported image (' . $mime . ').');
        }
        // an SVG from anywhere still gets the same scrubbing as an upload
        if ($mime === 'image/svg+xml'
            && preg_match('/<\s*script|javascript:|on[a-z]+\s*=|<!ENTITY/i', substr($body, 0, 512 * 1024))) {
            @unlink($tmp);
            throw new \RuntimeException('That SVG contains scripts and was rejected.');
        }

        $dir  = Uploads::ensureDir($bucket);
        $name = bin2hex(random_bytes(16)) . '.' . Uploads::IMAGE_TYPES[$mime];
        $dest = $dir . '/' . $name;

        // Write straight to the destination: tempnam() lands in the system temp
        // directory, which is frequently on a different filesystem (so rename()
        // fails) and may be mounted noexec/nosuid in containers.
        $written = @file_put_contents($dest, $body);
        @unlink($tmp);

        if ($written === false || $written !== strlen($body)) {
            throw new \RuntimeException(self::writeFailureReason($dir, $dest));
        }
        @chmod($dest, 0644);

        return [
            'stored_path' => 'uploads/' . basename($dir) . '/' . $name,
            'mime'        => $mime,
            'size'        => strlen($body),
        ];
    }


    /**
     * Explain exactly why a write failed, so the fix is obvious from the UI
     * rather than requiring a shell session to work out.
     */
    private static function writeFailureReason(string $dir, string $dest): string
    {
        $user = function_exists('posix_geteuid') && function_exists('posix_getpwuid')
            ? (posix_getpwuid(posix_geteuid())['name'] ?? 'the web server user')
            : 'the web server user';

        if (!is_dir($dir)) {
            return sprintf('The directory %s does not exist and could not be created. '
                . 'Run: mkdir -p %s && chown -R %s %s', $dir, $dir, $user, dirname($dir));
        }
        if (!is_writable($dir)) {
            $owner = 'unknown';
            if (function_exists('posix_getpwuid')) {
                $st = @stat($dir);
                $owner = $st ? (posix_getpwuid($st['uid'])['name'] ?? (string)$st['uid']) : 'unknown';
            }
            return sprintf(
                '%s is not writable by %s (it is owned by %s, mode %s). '
                . 'Fix it with: chown -R %s %s && chmod -R 775 %s',
                $dir, $user, $owner, substr(sprintf('%o', @fileperms($dir) ?: 0), -4),
                $user, dirname($dir), dirname($dir)
            );
        }
        $free = @disk_free_space($dir);
        if ($free !== false && $free < 1024 * 1024) {
            return sprintf('Only %s free on the volume holding %s — the image could not be written.',
                Uploads::human((int)$free), $dir);
        }
        return sprintf('Writing to %s failed even though it appears writable. '
            . 'Check for a read-only mount, a full disk, or SELinux/AppArmor restrictions.', $dest);
    }

    // ---------------- transport ----------------

    private static function httpGetJson(string $url): array
    {
        $raw = self::httpGetRaw($url, 2 * 1024 * 1024);
        $json = json_decode($raw, true);
        if (!is_array($json)) {
            throw new \RuntimeException('The image service returned an unexpected response.');
        }
        return $json;
    }

    private static function httpGetRaw(string $url, int $maxBytes): string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_TIMEOUT        => 20,
                CURLOPT_CONNECTTIMEOUT => 8,
                CURLOPT_USERAGENT      => self::UA,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_HTTPHEADER     => ['Accept: application/json, image/*'],
            ]);
            $body = curl_exec($ch);
            $err  = curl_error($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($body === false) {
                throw new \RuntimeException('Network error: ' . ($err ?: 'request failed')
                    . '. The server needs outbound HTTPS access for model image search.');
            }
            if ($code >= 400) {
                throw new \RuntimeException('The image service replied with HTTP ' . $code . '.');
            }
            if (strlen((string)$body) > $maxBytes) {
                throw new \RuntimeException('That image is larger than ' . Uploads::human($maxBytes) . '.');
            }
            return (string)$body;
        }

        $ctx = stream_context_create(['http' => [
            'timeout' => 20,
            'header'  => "User-Agent: " . self::UA . "\r\n",
        ]]);
        $body = @file_get_contents($url, false, $ctx, 0, $maxBytes + 1);
        if ($body === false) {
            throw new \RuntimeException('Could not reach the image service. The server needs outbound HTTPS access.');
        }
        return (string)$body;
    }
}
