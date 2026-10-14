<?php
/* ==================================================
   MVNBC backup ZIP download
   Streams a .zip of all backups for a given vendor, or all vendors.
   Usage:  download_zip.php?vendor=cisco
           download_zip.php?vendor=__all__
   Security: vendor must be a single path segment that resolves to a
   directory directly inside backups/. No traversal possible.
================================================== */
session_start();
if (!isset($_SESSION['logged_in'])) {
    http_response_code(401);
    die("Unauthorized");
}

$backupsRoot = realpath(__DIR__ . "/../backups");
if ($backupsRoot === false) {
    http_response_code(500);
    die("Backups directory not found");
}

$vendor = $_GET['vendor'] ?? '';

/* Allow only a safe slug: letters, digits, underscore, dash. Blocks ../, slashes, etc. */
if ($vendor !== '__all__' && !preg_match('/^[A-Za-z0-9_-]+$/', $vendor)) {
    http_response_code(400);
    die("Invalid vendor");
}

/* Resolve target(s) */
$targets = [];
if ($vendor === '__all__') {
    $targets[] = $backupsRoot;
    $zipBase   = "mvnbc_backups_all";
} else {
    $dir = realpath($backupsRoot . "/" . $vendor);
    // must exist, be a directory, and sit directly under backupsRoot
    if ($dir === false || !is_dir($dir) || strpos($dir, $backupsRoot . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(404);
        die("Vendor not found");
    }
    $targets[] = $dir;
    $zipBase   = "mvnbc_backups_" . $vendor;
}

/* Make sure there is at least one real backup file (ignore .gitkeep) */
$hasFiles = false;
foreach ($targets as $t) {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($t, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $f) {
        if ($f->isFile() && $f->getFilename() !== '.gitkeep') { $hasFiles = true; break 2; }
    }
}
if (!$hasFiles) {
    http_response_code(404);
    die("No backups available to download");
}

/* Build the zip in a temp file using the zip CLI (ZipArchive ext may be absent) */
$stamp   = date('Ymd_His');
$zipName = $zipBase . "_" . $stamp . ".zip";
$tmpZip  = tempnam(sys_get_temp_dir(), 'mvnbc_zip_');
if ($tmpZip === false) { http_response_code(500); die("Could not allocate temp file"); }
@unlink($tmpZip);
$tmpZip .= ".zip";

$zipBin = trim(shell_exec('command -v zip 2>/dev/null'));

$built = false;
if ($zipBin !== '') {
    if ($vendor === '__all__') {
        // zip the whole backups tree, store paths relative to backups/
        $cmd = sprintf(
            'cd %s && %s -r -q %s . -x ".gitkeep" 2>/dev/null',
            escapeshellarg($backupsRoot), escapeshellarg($zipBin), escapeshellarg($tmpZip)
        );
    } else {
        $cmd = sprintf(
            'cd %s && %s -r -q %s %s -x "*/.gitkeep" 2>/dev/null',
            escapeshellarg($backupsRoot), escapeshellarg($zipBin), escapeshellarg($tmpZip), escapeshellarg($vendor)
        );
    }
    shell_exec($cmd);
    $built = is_file($tmpZip) && filesize($tmpZip) > 0;
}

/* Fallback: PHP ZipArchive if the CLI was unavailable */
if (!$built && class_exists('ZipArchive')) {
    $za = new ZipArchive();
    if ($za->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
        foreach ($targets as $t) {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($t, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $f) {
                if (!$f->isFile() || $f->getFilename() === '.gitkeep') continue;
                $local = ltrim(str_replace($backupsRoot, '', $f->getPathname()), '/\\');
                $za->addFile($f->getPathname(), $local);
            }
        }
        $za->close();
        $built = is_file($tmpZip) && filesize($tmpZip) > 0;
    }
}

if (!$built) {
    @unlink($tmpZip);
    http_response_code(500);
    die("Could not create archive (zip tool unavailable)");
}

/* Stream it */
header('Content-Description: File Transfer');
header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="' . $zipName . '"');
header('Content-Length: ' . filesize($tmpZip));
header('Cache-Control: no-store');
readfile($tmpZip);
@unlink($tmpZip);
exit;
