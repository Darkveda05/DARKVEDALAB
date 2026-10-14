<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header("Location: login.php");
    exit;
}

/* SESSION TIMEOUT */
if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = time();
}

if (time() - $_SESSION['last_activity'] > 900) {
    session_destroy();
    header("Location: login.php?error=session");
    exit;
}

$_SESSION['last_activity'] = time();
clearstatcache(true);

/* DIRECTORIES */
$logDir = __DIR__ . "/../logs";

/* SAFE LOG LOADER */
function getLogs($dir) {
    if (!is_dir($dir)) return [];

    $files = glob($dir . "/*") ?: [];
    $files = array_filter($files, 'is_file');
    rsort($files);
    return $files;
}

$logFiles = getLogs($logDir);

require_once __DIR__ . '/app/includes/layout.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Logs · MVNBC</title>
<link rel="stylesheet" href="assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('logs', 'Run Logs', 'Backup job output and audit history'); ?>

<?php if (isset($_GET['deleted']) || isset($_GET['failed'])): ?>
    <?php $del = (int)($_GET['deleted'] ?? 0); $fl = (int)($_GET['failed'] ?? 0); ?>
    <div class="flash <?= $fl > 0 ? 'error' : 'success' ?>" id="flash">
        <?= mvnbc_icon($fl > 0 ? 'alert' : 'check') ?>
        <span><strong><?= $del ?></strong> log(s) deleted<?= $fl > 0 ? " · <strong>$fl</strong> failed" : "" ?>.</span>
        <span class="x" onclick="document.getElementById('flash').remove()">✕</span>
    </div>
<?php endif; ?>

<div class="panel">
    <div class="panel-head">
        <h2>Log Files</h2>
        <span class="count-chip"><?= count($logFiles) ?> file<?= count($logFiles) === 1 ? '' : 's' ?></span>
    </div>

    <?php if (empty($logFiles)): ?>
        <div class="empty">
            <?= mvnbc_icon('logs') ?>
            <h3>No logs yet</h3>
            <p>Run logs will appear here after the next scheduled backup.</p>
        </div>
    <?php else: ?>

    <form method="POST" action="bulk_delete.php" id="logForm">
        <input type="hidden" name="type" value="log">

        <div class="table-wrap">
        <table class="data">
            <thead>
            <tr>
                <th style="width:34px;"><input type="checkbox" onclick="toggleAllLogs(this)"></th>
                <th>Name</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Action</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($logFiles as $l): ?>
            <tr>
                <td><input type="checkbox" name="files[]" value="<?= htmlspecialchars($l) ?>"></td>
                <td class="file-name"><?= htmlspecialchars(basename($l)) ?></td>
                <td><?= file_exists($l) ? round(filesize($l)/1024, 2) : 0 ?> KB</td>
                <td class="mono"><?= file_exists($l) ? date("Y-m-d H:i:s", filemtime($l)) : '-' ?></td>
                <td>
                    <div class="row-actions">
                        <a href="view.php?file=<?= urlencode($l) ?>"><?= mvnbc_icon('eye') ?> View</a>
                        <a href="download.php?file=<?= urlencode($l) ?>"><?= mvnbc_icon('download') ?> Get</a>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>

        <div class="btn-row">
            <button type="button" class="btn btn-sm" onclick="selectAllLogs(true)">Select all</button>
            <button type="button" class="btn btn-sm" onclick="selectAllLogs(false)">Clear</button>
            <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Delete the selected logs?')">
                <?= mvnbc_icon('trash') ?> Delete selected
            </button>
        </div>
    </form>

    <?php endif; ?>
</div>

<script>
function selectAllLogs(state) {
    document.querySelectorAll('#logForm input[type=checkbox]').forEach(cb => cb.checked = state);
}
function toggleAllLogs(source) {
    document.querySelectorAll('#logForm input[type=checkbox]').forEach(cb => cb.checked = source.checked);
}
</script>

<?php mvnbc_shell_close(); ?>
</body>
</html>
