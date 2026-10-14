<?php
declare(strict_types=1);

namespace DarkVeda;

/**
 * IPv4/IPv6 helpers built on inet_pton binary representations,
 * so ordering / containment checks work for both families.
 */
final class IpTools
{
    /**
     * Parse "10.0.0.0/24" or "2001:db8::/64".
     * @return array{network:string, network_bin:string, prefix:int, version:int}|null
     */
    public static function parseCidr(string $cidr): ?array
    {
        $cidr = trim($cidr);
        if (!str_contains($cidr, '/')) {
            return null;
        }
        [$ip, $prefix] = explode('/', $cidr, 2);
        if (!ctype_digit($prefix)) {
            return null;
        }
        $prefix = (int)$prefix;
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        $version = strlen($bin) === 4 ? 4 : 6;
        $max = $version === 4 ? 32 : 128;
        if ($prefix < 0 || $prefix > $max) {
            return null;
        }
        $networkBin = self::applyMask($bin, $prefix);
        return [
            'network'     => inet_ntop($networkBin),
            'network_bin' => $networkBin,
            'prefix'      => $prefix,
            'version'     => $version,
        ];
    }

    /** Zero out host bits beyond the prefix. */
    public static function applyMask(string $bin, int $prefix): string
    {
        $bytes = strlen($bin);
        $out = '';
        for ($i = 0; $i < $bytes; $i++) {
            $bitsLeft = $prefix - $i * 8;
            if ($bitsLeft >= 8) {
                $out .= $bin[$i];
            } elseif ($bitsLeft <= 0) {
                $out .= "\x00";
            } else {
                $mask = chr((0xFF << (8 - $bitsLeft)) & 0xFF);
                $out .= $bin[$i] & $mask;
            }
        }
        return $out;
    }

    /** Is $ipBin inside network ($networkBin, $prefix)? Families must match. */
    public static function inSubnet(string $ipBin, string $networkBin, int $prefix): bool
    {
        if (strlen($ipBin) !== strlen($networkBin)) {
            return false;
        }
        return self::applyMask($ipBin, $prefix) === $networkBin;
    }

    /** Total usable host addresses (capped for display on huge v6 prefixes). */
    public static function usableHosts(int $version, int $prefix): string
    {
        if ($version === 4) {
            $total = 2 ** (32 - $prefix);
            // /31 (RFC 3021) and /32 have no network/broadcast overhead
            $usable = $prefix >= 31 ? $total : max($total - 2, 0);
            return (string)$usable;
        }
        $bits = 128 - $prefix;
        if ($bits > 63) {
            return '2^' . $bits;   // avoid overflow; display exponent form
        }
        return (string)(2 ** $bits);
    }

    /** Utilization % given assigned count; returns null when host count is astronomical. */
    public static function utilization(int $version, int $prefix, int $assigned): ?float
    {
        $usable = self::usableHosts($version, $prefix);
        if (!ctype_digit($usable) || (int)$usable === 0) {
            return null;
        }
        return round($assigned / (int)$usable * 100, 1);
    }

    /** Validate a bare IP; returns [address, bin, version] or null. */
    public static function parseIp(string $ip): ?array
    {
        $bin = @inet_pton(trim($ip));
        if ($bin === false) {
            return null;
        }
        return [
            'address' => inet_ntop($bin),
            'bin'     => $bin,
            'version' => strlen($bin) === 4 ? 4 : 6,
        ];
    }

    /** First free address in an IPv4 subnet given used binary addresses. Null for v6/full. */
    public static function firstFreeV4(string $networkBin, int $prefix, array $usedBins): ?string
    {
        if (strlen($networkBin) !== 4 || $prefix > 31) {
            return null;
        }
        $network = unpack('N', $networkBin)[1];
        $size = 2 ** (32 - $prefix);
        $start = $prefix >= 31 ? $network : $network + 1;          // skip network addr
        $end   = $prefix >= 31 ? $network + $size - 1 : $network + $size - 2; // skip broadcast
        $used = array_flip(array_map(fn($b) => unpack('N', $b)[1], $usedBins));
        for ($i = $start; $i <= $end; $i++) {
            if (!isset($used[$i])) {
                return long2ip($i);
            }
        }
        return null;
    }

    /** Binary -> printable address. */
    public static function ntop(string $bin): string
    {
        return inet_ntop($bin) ?: '';
    }

    /** Compare two same-family binary addresses (-1/0/1). */
    public static function cmpBin(string $a, string $b): int
    {
        return strcmp($a, $b) <=> 0;
    }

    /** Inclusive count of v4 addresses between two binaries; null for v6 / invalid. */
    public static function countBetweenV4(string $startBin, string $endBin): ?int
    {
        if (strlen($startBin) !== 4 || strlen($endBin) !== 4) {
            return null;
        }
        $s = unpack('N', $startBin)[1];
        $e = unpack('N', $endBin)[1];
        return $e >= $s ? $e - $s + 1 : null;
    }

    /**
     * Enumerate usable v4 host addresses of a subnet (skips network/broadcast
     * except /31 and /32). Returns list of dotted-quad strings, capped.
     */
    public static function enumerateV4(string $networkBin, int $prefix, int $cap = 1024): array
    {
        if (strlen($networkBin) !== 4 || $prefix < 0 || $prefix > 32) {
            return [];
        }
        $network = unpack('N', $networkBin)[1];
        $size    = 2 ** (32 - $prefix);
        $start   = $prefix >= 31 ? $network : $network + 1;
        $end     = $prefix >= 31 ? $network + $size - 1 : $network + $size - 2;
        $ips = [];
        for ($i = $start; $i <= $end && count($ips) < $cap; $i++) {
            $ips[] = long2ip($i);
        }
        return $ips;
    }
}
