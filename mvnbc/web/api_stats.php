<?php

header("Content-Type: application/json");

/* 🚀 FORCE NO CACHE */
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

/* =========================
   PATHS
========================= */
$backupDir  = realpath(__DIR__ . '/../backups');
$configFile = realpath(__DIR__ . '/../config/devices.conf');

/* =========================
   BACKUP VALIDATION
========================= */
function validateBackup($vendor, $file)
{
    if (!file_exists($file) || filesize($file) <= 0) {
        return false;
    }

    $content = @file_get_contents($file);

    if ($content === false) {
        return false;
    }

    switch (strtolower($vendor)) {

        case 'cisco':
            return preg_match(
                '/Current configuration|Building configuration|^hostname /m',
                $content
            );

        case 'ciscoasa':
            return preg_match(
                '/^ASA Version|^hostname /m',
                $content
            );

        case 'mikrotik':
		    return (
               stripos($content, 'RouterOS') !== false &&
               (
					stripos($content, '/interface') !== false ||
					stripos($content, '/ip ') !== false ||
					stripos($content, '/system ') !== false
				)
			);

        case 'h3c':
			if (preg_match(
				'/SSH CONNECTION FAILED|LOGIN FAILED|TIMEOUT|Connection refused/i',
				$content
			)) {
			return false;
			}

			return preg_match(
			'/^sysname |System View|display cu|display current-configuration/m',
				$content
			);
			
		case 'h3c_1920':
			if (preg_match(
				'/SSH CONNECTION FAILED|LOGIN FAILED|TIMEOUT|Connection refused/i',
				$content
			)) {
			return false;
			}

			return preg_match(
			'/^sysname |System View|display cu|display current-configuration/m',
				$content
			);	

        case 'arista':
		    if (preg_match(
				'/Connection refused|Permission denied|TIMEOUT|LOGIN FAILED/i',
				$content
			)) {
			return false;
			}

			return preg_match(
				'/! Command: show running-config|hostname |interface Ethernet|router /i',
			$content
			);

        case 'aruba':
			if (preg_match(
				'/LOGIN FAILED|TIMEOUT|Connection refused|Permission denied/i',
				$content
			)) {
			return false;
			}

            return preg_match(
               '/Current configuration:|^hostname |^user admin |^vlan /mi',
            $content
			);
			
		case 'fortigate':
			if (preg_match(
				'/No route to host|Connection refused|Connection timed out|LOGIN FAILED|ssh:/i',
				$content
			)) {
			return false;
			}

			return preg_match(
				'/#config-version=|config system|config firewall/i',
			$content
			);
			
		case 'juniper':
			if (preg_match(
				'/LOGIN FAILED|Connection refused|No route to host|timed out|ssh:/i',
			$content
			)) {
			return false;
			}
			return preg_match(
				'/^set system|^set interfaces|^set routing-options/m',
			$content
			);
	

        default:
            return filesize($file) > 0;
    }
}

/* =========================
   INIT
========================= */
$total = 0;
$ok = 0;
$fail = 0;

$vendors = [];

/* NEW */
$fileTotal = 0;
$fileOk = 0;
$fileFail = 0;

/* =========================
   READ DEVICES
========================= */
if (!file_exists($configFile)) {

    echo json_encode([
        "error" => "devices.conf not found"
    ]);

    exit;
}

$lines = file(
    $configFile,
    FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
);

foreach ($lines as $line) {

    $line = trim($line);

    if ($line === "" || $line[0] === "#") {
        continue;
    }

    $parts = explode(",", $line);

    if (count($parts) < 2) {
        continue;
    }

    $vendor = trim($parts[0]);
    $ip     = trim($parts[1]);

    $vendorDir = $backupDir . "/" . $vendor;

    $status = "FAIL";
    $latestFile = null;

    /* =========================
       FIND LATEST BACKUP FILE
    ========================= */
if (is_dir($vendorDir)) {

    $files = glob($vendorDir . "/" . $ip . "_*.log");

    if ($files && count($files) > 0) {

        usort($files, function ($a, $b) {
            return filemtime($b) <=> filemtime($a);
        });

        $latestFile = null;

        foreach ($files as $f) {

            // Skip files modified within last 30 seconds
            if ((time() - filemtime($f)) > 30) {
                $latestFile = $f;
                break;
            }
        }

        // If all files are new, use newest anyway
        if ($latestFile === null) {
            $latestFile = $files[0];
        }

        $status = validateBackup($vendor, $latestFile)
            ? "OK"
            : "FAIL";
			
    }
}

    /* =========================
       GLOBAL COUNTERS
    ========================= */
    $total++;

    if ($status === "OK") {
        $ok++;
    } else {
        $fail++;
    }


     /* =========================
   FILE STATISTICS
========================= */

if (is_dir($vendorDir)) {

    $allFiles = glob($vendorDir . "/*") ?: [];

    foreach ($allFiles as $f) {

        if (!is_file($f)) {
            continue;
        }

        $fileTotal++;

        $content = @file_get_contents($f);

        $valid = false;

        switch (strtolower($vendor)) {

            case 'cisco':
                $valid = preg_match(
                    '/Current configuration|Building configuration|hostname/i',
                    $content
                );
                break;

            case 'ciscoasa':
                $valid = preg_match(
                    '/ASA Version|hostname/i',
                    $content
                );
                break;

            case 'mikrotik':
                $valid =
                    stripos($content, 'RouterOS') !== false &&
                    (
                        stripos($content, '/interface') !== false ||
                        stripos($content, '/ip ') !== false ||
                        stripos($content, '/system ') !== false
                    );
                break;

            case 'h3c':

				if (preg_match(
					'/SSH CONNECTION FAILED|LOGIN FAILED|TIMEOUT|Connection refused/i',
					$content
				)) {
				$valid = false;
				break;
				}

				$valid = preg_match(
					'/^sysname |System View|display cu|display current-configuration/i',
				$content
				);
			break;
			
			case 'h3c_1920':
				if (preg_match(
					'/SSH CONNECTION FAILED|LOGIN FAILED|TIMEOUT|Connection refused/i',
					$content
				)) {
				$valid = false;
			} else {
			$valid = preg_match(
            '/sysname|System View|display cu|display current-configuration/i',
            $content
				);
				}
			break;

            case 'arista':
				if (preg_match(
				'/Connection refused|Permission denied|TIMEOUT|LOGIN FAILED/i',
				$content
				)) {
				$valid = false;
				break;
				}
				
				$valid = preg_match(
				'/! Command: show running-config|hostname |interface Ethernet|router /i',
				$content
				);
				break;

            case 'aruba':
				if (preg_match(
					'/LOGIN FAILED|TIMEOUT|Connection refused|Permission denied/i',
				$content
				)) {
				$valid = false;
			break;
			}

			$valid = preg_match(
				'/Current configuration:|hostname|user admin|vlan /i',
			$content
			);
			break;
			
			case 'fortigate':
				if (preg_match(
				'/No route to host|Connection refused|Connection timed out|LOGIN FAILED|ssh:/i',
				$content
				)) {
				$valid = false;
				} else {
					$valid = preg_match(
					'/#config-version=|config system|config firewall/i',
					$content
					);
				}
			break;
			
			case 'juniper':
				if (preg_match(
				'/LOGIN FAILED|Connection refused|No route to host|timed out|ssh:/i',
				$content
				)) {
				$valid = false;
				} else {
					$valid = preg_match(
					'/^set system|^set interfaces|^set routing-options/m',
					$content
					);
				}
			break;
        }

        if ($valid) {
            $fileOk++;
        } else {
            $fileFail++;
        }
    }
}

    /* =========================
       VENDOR GROUPING
    ========================= */
    if (!isset($vendors[$vendor])) {

        $vendors[$vendor] = [
            "vendor" => $vendor,
            "count"  => 0,
            "ok"     => 0,
            "fail"   => 0,
            "last"   => "-"
        ];
    }

    $vendors[$vendor]["count"]++;

    if ($status === "OK") {

        $vendors[$vendor]["ok"]++;

        if ($latestFile) {
            $vendors[$vendor]["last"] =
                date("Y-m-d H:i:s", filemtime($latestFile));
        }

    } else {

        $vendors[$vendor]["fail"]++;
    }
}

/* =========================
   OUTPUT JSON
========================= */
echo json_encode([
    "total" => $total,
    "ok" => $ok,
    "fail" => $fail,

    /* Device Health */
    "vendors" => array_values($vendors),

    /* Backup History */
    "file_total" => $fileTotal,
    "file_ok" => $fileOk,
    "file_fail" => $fileFail
]);