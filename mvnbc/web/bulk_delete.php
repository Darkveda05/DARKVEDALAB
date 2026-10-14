<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header("Location: login.php");
    exit;
}

$files = $_POST['files'] ?? [];
$type  = $_POST['type'] ?? '';

if (empty($files)) {
    header("Location: index.php");
    exit;
}

$baseDir = realpath(__DIR__ . "/..");
$auditLog = __DIR__ . "/../logs/delete_audit.log";

$deleted = 0;
$failed  = 0;

/* =========================
   AUDIT FUNCTION
========================= */
function writeAudit($auditLog, $status, $file)
{
    $user = $_SESSION['username'] ?? 'unknown';
    $entry = date("Y-m-d H:i:s") . " | $user | $status | $file\n";
    file_put_contents($auditLog, $entry, FILE_APPEND);
}

/* =========================
   DELETE LOOP
========================= */
foreach ($files as $file) {

    $real = realpath($file);

    /* STEP 1: validate */
    if (!$real || !file_exists($real)) {
        writeAudit($auditLog, "NOT FOUND", $file);
        $failed++;
        continue;
    }

    /* STEP 2: security - base directory */
    if (strpos($real, $baseDir) !== 0) {
        writeAudit($auditLog, "BLOCKED (OUTSIDE BASE)", $real);
        $failed++;
        continue;
    }

    /* STEP 3: allow only backups + logs */
    if (
        strpos($real, '/backups/') === false &&
        strpos($real, '/logs/') === false
    ) {
        writeAudit($auditLog, "BLOCKED (INVALID PATH)", $real);
        $failed++;
        continue;
    }

    /* STEP 4: skip directories */
    if (is_dir($real)) {
        writeAudit($auditLog, "SKIP DIR", $real);
        continue;
    }

    clearstatcache(true);

    writeAudit($auditLog, "TRY DELETE", $real);

    /* STEP 5: permission check */
    if (!is_writable($real)) {
        writeAudit($auditLog, "NOT WRITABLE", $real);
        $failed++;
        continue;
    }

    /* STEP 6: delete */
    if (@unlink($real)) {
        writeAudit($auditLog, "DELETED OK", $real);
        $deleted++;
    } else {
        $err = error_get_last();
        $msg = $err['message'] ?? 'unknown error';

        writeAudit($auditLog, "UNLINK FAILED | msg=" . $msg, $real);
        $failed++;
    }
}

/* =========================
   REDIRECT WITH RESULT
========================= */
header("Location: index.php?deleted=$deleted&failed=$failed&t=" . time());
exit;