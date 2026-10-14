<?php
session_start();
if (!isset($_SESSION['logged_in'])) {
    header("Location: ../../login.php");
    exit;
}

require_once __DIR__ . '/../includes/layout.php';

$BASE_DIR = realpath(__DIR__ . "/../../..");
$script   = $BASE_DIR . "/MVNBC.sh";
$jobCmd   = "/bin/bash " . $script . " --auto";
$marker   = $script;   // we identify our job line by the script path

$msg = ""; $ok = false;
$cronWriteBlocked = false;   // crontab exists but the web user can't write it
$blockedCron = '';

/* crontab availability */
$cronBin = trim(@shell_exec('command -v crontab 2>/dev/null'));
$cronAvailable = ($cronBin !== '');

function read_crontab() {
    $out = @shell_exec('crontab -l 2>/dev/null');
    return $out === null ? '' : $out;
}

function current_job_line($marker) {
    $lines = explode("\n", read_crontab());
    foreach ($lines as $l) {
        if (strpos($l, $marker) !== false && strlen(trim($l)) && $l[0] !== '#') {
            return trim($l);
        }
    }
    return '';
}

/* Validate a 5-field cron expression (basic but effective) */
function valid_cron($expr) {
    $parts = preg_split('/\s+/', trim($expr));
    if (count($parts) !== 5) return false;
    foreach ($parts as $p) {
        if (!preg_match('#^[\d\*/,\-]+$#', $p)) return false;
    }
    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $cronAvailable) {
    $action = $_POST['action'] ?? '';

    if ($action === 'save') {
        $preset = $_POST['preset'] ?? 'daily';
        if ($preset === 'daily')      $cron = '0 2 * * *';
        elseif ($preset === 'weekly') $cron = '0 2 * * 0';
        elseif ($preset === 'hourly') $cron = '0 * * * *';
        else                          $cron = trim($_POST['custom_cron'] ?? '');

        if (!valid_cron($cron)) {
            $msg = "That cron expression doesn't look valid. Use 5 fields, e.g. 0 2 * * *";
        } else {
            // rebuild crontab: keep everything except our previous job, then append
            $existing = explode("\n", read_crontab());
            $kept = [];
            foreach ($existing as $l) {
                if (trim($l) === '') continue;
                if (strpos($l, $marker) !== false) continue; // drop old MVNBC job
                $kept[] = $l;
            }
            $kept[] = $cron . " " . $jobCmd;
            $newCron = implode("\n", $kept) . "\n";

            $proc = proc_open('crontab - 2>&1', [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
            if (is_resource($proc)) {
                fwrite($pipes[0], $newCron);
                fclose($pipes[0]);
                $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
                $err = trim(stream_get_contents($pipes[2]) . $out); fclose($pipes[2]);
                $code = proc_close($proc);
                if ($code === 0) {
                    $msg = "Schedule saved."; $ok = true;
                } elseif (stripos($err, 'suid') !== false || stripos($err, 'permission') !== false || stripos($err, 'allowed') !== false) {
                    // BusyBox/containerised crontab that the web user can't write.
                    $cronWriteBlocked = true;
                    $blockedCron = $cron;
                    $msg = "The web user isn't allowed to write crontab on this host. Add the line below to your crontab manually instead.";
                } else {
                    $msg = "Failed to write crontab: " . ($err !== '' ? $err : 'unknown error');
                }
            } else {
                $msg = "Could not run crontab.";
            }
        }
    } elseif ($action === 'remove') {
        $existing = explode("\n", read_crontab());
        $kept = [];
        foreach ($existing as $l) {
            if (trim($l) === '') continue;
            if (strpos($l, $marker) !== false) continue;
            $kept[] = $l;
        }
        $newCron = empty($kept) ? "" : implode("\n", $kept) . "\n";
        $proc = proc_open('crontab -', [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
        if (is_resource($proc)) {
            fwrite($pipes[0], $newCron); fclose($pipes[0]);
            stream_get_contents($pipes[1]); fclose($pipes[1]);
            stream_get_contents($pipes[2]); fclose($pipes[2]);
            $code = proc_close($proc);
            if ($code === 0) { $msg = "Schedule removed."; $ok = true; }
            else { $msg = "Failed to update crontab."; }
        }
    }
}

$activeJob = $cronAvailable ? current_job_line($marker) : '';

/* describe a known cron in friendly terms */
function describe_cron($line, $marker) {
    $expr = trim(str_replace($marker, '', str_replace('/bin/bash', '', $line)));
    $expr = trim(preg_replace('/--auto.*$/', '', $expr));
    $map = [
        '0 2 * * *' => 'Every day at 02:00',
        '0 2 * * 0' => 'Every Sunday at 02:00',
        '0 * * * *' => 'Every hour',
    ];
    foreach ($map as $k => $v) if (strpos($line, $k) !== false) return $v;
    return 'Custom schedule';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Schedule · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('schedule', 'Schedule', 'Automate backups with cron', '../../'); ?>

<?php if ($msg): ?>
    <div class="flash <?= $ok ? 'success' : 'error' ?>">
        <?= mvnbc_icon($ok ? 'check' : 'alert') ?>
        <span><?= htmlspecialchars($msg) ?></span>
    </div>
<?php endif; ?>

<?php if ($cronWriteBlocked): ?>
    <div class="note" style="border-left-color: var(--warn);">
        <p style="margin:0 0 10px;"><?= mvnbc_icon('alert') ?> <strong>This host's <code>crontab</code> needs root/suid to install jobs</strong> (common on BusyBox, CasaOS, and other container setups). The web user can't write it directly. To schedule the backup, add this line to the crontab of the user that owns the project:</p>
        <pre><?= htmlspecialchars($blockedCron . ' ' . $jobCmd) ?></pre>
        <p style="margin:10px 0 0;">Open a shell on the host and run <code>crontab -e</code> (use <code>sudo crontab -e</code> if needed), paste the line, then save. The one-click <strong>Run backup now</strong> button above keeps working regardless.</p>
    </div>
<?php endif; ?>

<!-- RUN NOW -->
<div class="panel">
    <div class="panel-head"><h2>Run backup now</h2></div>
    <p class="muted-text">Trigger a full backup of every device in the inventory immediately. Progress appears below.</p>
    <div class="btn-row">
        <button id="runBtn" class="btn btn-primary" onclick="startRun()"><?= mvnbc_icon('refresh') ?> Run backup now</button>
        <span id="runState" class="run-state"></span>
    </div>
    <div id="runFeed" class="run-feed" style="display:none;"></div>
</div>

<!-- SCHEDULE -->
<div class="panel">
    <div class="panel-head">
        <h2>Scheduled backup</h2>
        <?php if ($activeJob): ?>
            <span class="pill ok">active</span>
        <?php else: ?>
            <span class="pill muted">not scheduled</span>
        <?php endif; ?>
    </div>

    <?php if (!$cronAvailable): ?>
        <div class="note">
            <p style="margin:0 0 10px;"><?= mvnbc_icon('alert') ?> <strong>cron isn't available to the web user on this host</strong>, so the schedule can't be managed from here. Add this line to your crontab manually instead:</p>
            <pre>0 2 * * * <?= htmlspecialchars($jobCmd) ?></pre>
            <p style="margin:10px 0 0;">Run <code>crontab -e</code> as the user that owns the project, paste the line, and save.</p>
        </div>
    <?php else: ?>

        <?php if ($activeJob): ?>
            <div class="sched-current">
                <div>
                    <div class="sched-desc"><?= htmlspecialchars(describe_cron($activeJob, $marker)) ?></div>
                    <div class="sched-cron mono"><?= htmlspecialchars($activeJob) ?></div>
                </div>
                <form method="POST" onsubmit="return confirm('Remove the scheduled backup?');" style="margin:0;">
                    <input type="hidden" name="action" value="remove">
                    <button type="submit" class="btn btn-danger btn-sm"><?= mvnbc_icon('trash') ?> Remove</button>
                </form>
            </div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="action" value="save">
            <div class="seg-field">
                <label class="radio-tile">
                    <input type="radio" name="preset" value="daily" checked onclick="toggleCustom(false)">
                    <span><strong>Daily</strong><small>Every day at 02:00</small></span>
                </label>
                <label class="radio-tile">
                    <input type="radio" name="preset" value="weekly" onclick="toggleCustom(false)">
                    <span><strong>Weekly</strong><small>Sundays at 02:00</small></span>
                </label>
                <label class="radio-tile">
                    <input type="radio" name="preset" value="hourly" onclick="toggleCustom(false)">
                    <span><strong>Hourly</strong><small>At minute 0 of every hour</small></span>
                </label>
                <label class="radio-tile">
                    <input type="radio" name="preset" value="custom" onclick="toggleCustom(true)">
                    <span><strong>Custom</strong><small>Your own cron expression</small></span>
                </label>
            </div>
            <div id="customWrap" style="display:none; margin-top:16px; max-width:340px;">
                <label class="field-label">Cron expression</label>
                <input class="input mono" type="text" name="custom_cron" placeholder="*/30 * * * *">
                <p class="hint">minute hour day month weekday</p>
            </div>
            <div class="btn-row">
                <button type="submit" class="btn btn-primary"><?= mvnbc_icon('save') ?> Save schedule</button>
            </div>
        </form>
    <?php endif; ?>
</div>

<script>
function toggleCustom(show){ document.getElementById('customWrap').style.display = show ? 'block':'none'; }

let pollTimer = null;
async function startRun(){
    const btn = document.getElementById('runBtn');
    const state = document.getElementById('runState');
    btn.disabled = true;
    state.textContent = 'Starting…';
    try {
        const fd = new FormData(); fd.append('action','start');
        const r = await fetch('../../run_backup.php', { method:'POST', body: fd });
        const d = await r.json();
        if (d.started === false) { state.textContent = d.reason || 'Could not start'; btn.disabled = false; return; }
        document.getElementById('runFeed').style.display = 'block';
        pollStatus();
        pollTimer = setInterval(pollStatus, 2500);
    } catch(e){ state.textContent = 'Error starting backup'; btn.disabled = false; }
}

async function pollStatus(){
    const state = document.getElementById('runState');
    const feed = document.getElementById('runFeed');
    const btn = document.getElementById('runBtn');
    try {
        const r = await fetch('../../run_backup.php?status=1');
        const d = await r.json();
        if (d.lines && d.lines.length) {
            feed.innerHTML = d.lines.map(l => '<div class="feed-line">'+escapeHtml(l)+'</div>').join('');
        }
        if (d.running) {
            state.textContent = 'Running… ' + d.ok + ' ok / ' + d.fail + ' failed';
        } else if (d.finished) {
            clearInterval(pollTimer);
            state.innerHTML = '<span class="done-ok">Done — ' + d.ok + ' ok, ' + d.fail + ' failed</span>';
            btn.disabled = false;
        } else {
            state.textContent = 'Starting…';
        }
    } catch(e){ /* keep polling */ }
}

function escapeHtml(s){ return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
</script>

<?php mvnbc_shell_close(); ?>
</body>
</html>
