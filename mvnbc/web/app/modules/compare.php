<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header("Location: ../../login.php");
    exit;
}

/* ROOT PATH */
define("ROOT_PATH", realpath(__DIR__ . "/../../.."));
$backupDir = ROOT_PATH . "/backups";

/* GET ALL FILES (ALL VENDORS) */
function getAllFiles($dir)
{
    $vendors = glob($dir . "/*", GLOB_ONLYDIR);
    $all = array();

    if ($vendors) {
        foreach ($vendors as $vendorPath) {
            $files = glob($vendorPath . "/*");
            if ($files) {
                foreach ($files as $f) {
                    if (is_file($f)) {
                        $all[] = $f;
                    }
                }
            }
        }
    }

    rsort($all);
    return $all;
}

function getVendor($filePath)
{
    $parts = explode(DIRECTORY_SEPARATOR, $filePath);
    return isset($parts[count($parts) - 2]) ? $parts[count($parts) - 2] : 'UNKNOWN';
}

$files = getAllFiles($backupDir);

$f1 = isset($_POST['file1']) ? $_POST['file1'] : '';
$f2 = isset($_POST['file2']) ? $_POST['file2'] : '';

require_once __DIR__ . '/../includes/layout.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compare · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('compare', 'Config Compare', 'Diff two backup snapshots line by line', '../../'); ?>

<div class="panel">
    <div class="panel-head"><h2>Select Two Snapshots</h2></div>

    <?php if (empty($files)): ?>
        <div class="empty">
            <?= mvnbc_icon('inbox') ?>
            <h3>No backups to compare</h3>
            <p>At least two backup files are needed to run a diff.</p>
        </div>
    <?php else: ?>
    <form method="POST">
        <div class="compare-meta" style="margin-top:0;">
            <div>
                <label class="field-label">Baseline (old)</label>
                <select name="file1" required>
                    <option value="">Select a file…</option>
                    <?php foreach ($files as $f): ?>
                        <option value="<?= htmlspecialchars($f) ?>" <?= $f === $f1 ? 'selected' : '' ?>>
                            <?= htmlspecialchars(getVendor($f) . " / " . basename($f)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="field-label">Comparison (new)</label>
                <select name="file2" required>
                    <option value="">Select a file…</option>
                    <?php foreach ($files as $f): ?>
                        <option value="<?= htmlspecialchars($f) ?>" <?= $f === $f2 ? 'selected' : '' ?>>
                            <?= htmlspecialchars(getVendor($f) . " / " . basename($f)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <button type="submit" class="btn btn-primary"><?= mvnbc_icon('compare') ?> Run diff</button>
    </form>
    <?php endif; ?>
</div>

<?php if ($f1 && $f2 && file_exists($f1) && file_exists($f2)):
    $c1 = file($f1, FILE_IGNORE_NEW_LINES);
    $c2 = file($f2, FILE_IGNORE_NEW_LINES);
    $added   = array_filter($c2, fn($l) => !in_array($l, $c1));
    $removed = array_filter($c1, fn($l) => !in_array($l, $c2));
?>

<div class="panel">
    <div class="panel-head">
        <h2>Diff Result</h2>
        <span class="spacer"></span>
        <span class="count-chip" style="color:var(--ok)"><?= count($added) ?> added</span>
        <span class="count-chip" style="color:var(--fail)"><?= count($removed) ?> removed</span>
    </div>

    <div class="compare-meta">
        <div class="cm">
            <div class="cm-tag">Baseline · <?= htmlspecialchars(getVendor($f1)) ?></div>
            <div class="cm-val"><?= htmlspecialchars(basename($f1)) ?></div>
        </div>
        <div class="cm">
            <div class="cm-tag">Comparison · <?= htmlspecialchars(getVendor($f2)) ?></div>
            <div class="cm-val"><?= htmlspecialchars(basename($f2)) ?></div>
        </div>
    </div>

    <div class="diff" style="margin-bottom:16px;">
        <div class="diff-section-label add">Added in new config</div>
        <?php if (empty($added)): ?>
            <div class="empty-diff">No added lines.</div>
        <?php else: ?>
            <pre><?php foreach ($added as $line) echo '<span class="ln-add">+ ' . htmlspecialchars($line) . "</span>\n"; ?></pre>
        <?php endif; ?>
    </div>

    <div class="diff">
        <div class="diff-section-label rem">Removed from old config</div>
        <?php if (empty($removed)): ?>
            <div class="empty-diff">No removed lines.</div>
        <?php else: ?>
            <pre><?php foreach ($removed as $line) echo '<span class="ln-rem">- ' . htmlspecialchars($line) . "</span>\n"; ?></pre>
        <?php endif; ?>
    </div>
</div>

<?php endif; ?>

<?php mvnbc_shell_close(); ?>
</body>
</html>
