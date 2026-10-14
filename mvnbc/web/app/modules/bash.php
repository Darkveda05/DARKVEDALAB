<?php
session_start();
if (!isset($_SESSION['logged_in'])) die("Unauthorized");

$file = @file_get_contents("../../../MVNBC.sh");
if ($file === false) $file = "";
$lines = substr_count($file, "\n") + 1;

require_once __DIR__ . '/../includes/layout.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backup Script · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('bash', 'Backup Script', 'The engine that drives every scheduled backup', '../../'); ?>

<div class="panel">
    <div class="panel-head"><h2>MVNBC.sh</h2><span class="count-chip"><?= $lines ?> lines · read only</span></div>
    <textarea class="code-area" readonly><?= htmlspecialchars($file) ?></textarea>

    <div class="note">
        <h4>Editing the backup script</h4>
        <p>The script is edited from the server shell to keep execution permissions and logic under root control:</p>
        <pre>nano MVNBC.sh</pre>
        <p class="restricted"><?= mvnbc_icon('lock') ?> Restricted: only root administrators may modify this file.</p>
    </div>
</div>

<?php mvnbc_shell_close(); ?>
</body>
</html>
