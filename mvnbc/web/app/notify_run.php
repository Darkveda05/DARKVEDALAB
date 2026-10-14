<?php
/* ==================================================
   MVNBC run notifier (CLI)
   Usage:  php notify_run.php [path-to-run-log]
   Reads the latest (or given) run log, summarises OK/FAIL,
   and dispatches Email/Telegram alerts per settings.json.
   Called automatically by MVNBC.sh at the end of a run.
================================================== */

require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/notify.php';

$base    = realpath(__DIR__ . '/../..');
$logDir  = $base . '/logs';

/* locate the run log */
$logFile = $argv[1] ?? '';
if ($logFile === '' || !is_file($logFile)) {
    // pick the newest run_*.log
    $candidates = glob($logDir . '/run_*.log');
    if ($candidates) {
        usort($candidates, function($a,$b){ return filemtime($b) - filemtime($a); });
        $logFile = $candidates[0];
    }
}

if (!$logFile || !is_file($logFile)) {
    fwrite(STDERR, "notify_run: no run log found\n");
    exit(0);
}

$content = file_get_contents($logFile);
$lines = explode("\n", $content);

$okList = [];
$failList = [];
foreach ($lines as $ln) {
    if (preg_match('/^\[OK\] Backup saved: .*\/([^\/]+)$/', $ln, $m)) {
        $okList[] = $m[1];
    } elseif (preg_match('/^\[FAIL\] Backup validation failed: (.+)$/', $ln, $m)) {
        $failList[] = trim($m[1]);
    }
}

$okCount   = count($okList);
$failCount = count($failList);
$total     = $okCount + $failCount;

$settings = mvnbc_load_settings();
$mode = $settings['alerts']['notify_on'] ?? 'failure';

if ($mode === 'never') { exit(0); }
if ($mode === 'failure' && $failCount === 0) { exit(0); }

/* build summary */
$host = gethostname() ?: 'server';
date_default_timezone_set('Asia/Kuala_Lumpur');
$when = date('Y-m-d H:i:s') . ' MYT';
$status = $failCount === 0 ? 'SUCCESS' : 'FAILURES';

$subject = "MVNBC backup $status — $okCount ok, $failCount failed";

$body  = "MVNBC backup run summary\n";
$body .= "Host:    $host\n";
$body .= "Time:    $when\n";
$body .= "Result:  $okCount succeeded, $failCount failed (of $total)\n";
$body .= str_repeat('-', 40) . "\n";

if ($failCount > 0) {
    $body .= "FAILED:\n";
    foreach ($failList as $f) $body .= "  ✗ $f\n";
    $body .= "\n";
}
if ($okCount > 0) {
    $body .= "OK:\n";
    foreach ($okList as $o) $body .= "  ✓ $o\n";
}
$body .= "\nLog: " . basename($logFile) . "\n";

$results = mvnbc_dispatch_alert($settings, $subject, $body);

foreach ($results as $channel => $r) {
    [$ok, $m] = $r;
    fwrite(STDOUT, sprintf("notify_run[%s]: %s — %s\n", $channel, $ok ? 'OK' : 'ERR', $m));
}
exit(0);
