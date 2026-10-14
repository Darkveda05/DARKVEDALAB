<?php
/* ==================================================
   MVNBC one-click backup runner
   POST action=start   -> launches MVNBC.sh --auto in the background
   GET  ?status=1      -> returns JSON about the latest/running run
   Uses a lock + state file so the UI can poll progress.
================================================== */
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['logged_in'])) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    exit;
}

$base    = realpath(__DIR__ . "/..");          // project root
$script  = $base . "/MVNBC.sh";
$logDir  = $base . "/logs";
$stateFile = $logDir . "/.run_state.json";
$lockFile  = $logDir . "/.run.lock";

@mkdir($logDir, 0775, true);

function latest_run_log($logDir) {
    $logs = glob($logDir . "/run_*.log");
    if (!$logs) return null;
    usort($logs, function($a,$b){ return filemtime($b) - filemtime($a); });
    return $logs[0];
}

function parse_progress($logFile) {
    if (!$logFile || !is_file($logFile)) return ['ok'=>0,'fail'=>0,'done'=>false,'lines'=>[]];
    $txt = file_get_contents($logFile);
    $lines = explode("\n", $txt);
    $ok = 0; $fail = 0; $done = false; $tail = [];
    foreach ($lines as $l) {
        if (strpos($l, '[OK] Backup saved:') === 0) $ok++;
        elseif (strpos($l, '[FAIL]') === 0) $fail++;
        if (strpos($l, '[DONE]') === 0) $done = true;
    }
    // last few meaningful lines for a live feed
    $clean = array_values(array_filter(array_map('trim', $lines), function($x){ return $x !== ''; }));
    $tail = array_slice($clean, -8);
    return ['ok'=>$ok,'fail'=>$fail,'done'=>$done,'lines'=>$tail];
}

function is_running($lockFile) {
    if (!is_file($lockFile)) return false;
    $pid = (int)trim(@file_get_contents($lockFile));
    if ($pid <= 0) return false;
    // posix or /proc check
    if (function_exists('posix_kill')) return @posix_kill($pid, 0);
    return is_dir("/proc/$pid");
}

/* ---------- STATUS ---------- */
if (($_GET['status'] ?? '') === '1' || $_SERVER['REQUEST_METHOD'] === 'GET') {
    $running = is_running($lockFile);
    $logFile = latest_run_log($logDir);
    $progress = parse_progress($logFile);
    // run considered finished when not running AND log shows DONE
    $finished = !$running && $progress['done'];
    echo json_encode([
        'running'  => $running,
        'finished' => $finished,
        'ok'       => $progress['ok'],
        'fail'     => $progress['fail'],
        'lines'    => $progress['lines'],
        'log'      => $logFile ? basename($logFile) : null,
    ]);
    exit;
}

/* ---------- START ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'start') {

    if (!is_file($script)) {
        echo json_encode(['error' => 'MVNBC.sh not found']);
        exit;
    }
    if (is_running($lockFile)) {
        echo json_encode(['started' => false, 'reason' => 'A backup is already running']);
        exit;
    }

    // Launch in the background, detached, writing a pid into the lock file.
    // The script itself writes run_<id>.log; we just need it to run async.
    $cmd = sprintf(
        '%s %s --auto >/dev/null 2>&1 & echo $!',
        escapeshellarg('/bin/bash'),
        escapeshellarg($script)
    );

    $pid = 0;
    if (function_exists('proc_open')) {
        $descr = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
        $proc = proc_open('/bin/bash -c ' . escapeshellarg($cmd), $descr, $pipes, $base);
        if (is_resource($proc)) {
            $pid = (int)trim(stream_get_contents($pipes[1]));
            foreach ($pipes as $p) { if (is_resource($p)) fclose($p); }
            proc_close($proc);
        }
    }
    if ($pid <= 0 && function_exists('shell_exec')) {
        $pid = (int)trim(shell_exec($cmd));
    }

    if ($pid > 0) {
        @file_put_contents($lockFile, $pid);
        echo json_encode(['started' => true, 'pid' => $pid]);
    } else {
        echo json_encode(['started' => false, 'reason' => 'Could not launch backup process']);
    }
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'bad request']);
