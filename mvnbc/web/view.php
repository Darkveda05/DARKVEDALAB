<?php
session_start();

if (!isset($_SESSION["logged_in"])) {
    die("Unauthorized");
}

/* PATH SECURITY */
$allowedDirs = [
    realpath(__DIR__ . "/../backups"),
    realpath(__DIR__ . "/../logs")
];

$file = realpath($_GET["file"] ?? "");

$valid = false;
foreach ($allowedDirs as $dir) {
    if ($file && $dir && strpos($file, $dir) === 0) {
        $valid = true;
    }
}

if (!$valid || !file_exists($file)) {
    die("Invalid file");
}

$content  = htmlspecialchars(file_get_contents($file));
$filename = basename($file);
$size     = round(filesize($file) / 1024, 2);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($filename) ?> · MVNBC</title>
<link rel="stylesheet" href="assets/style.css?v=6">
</head>
<body>

<div class="main" style="grid-column:1/-1;max-width:1100px;margin:0 auto;width:100%;">
    <div class="topbar">
        <div>
            <h1>File Viewer</h1>
            <div class="page-sub"><?= htmlspecialchars($filename) ?> · <?= $size ?> KB</div>
        </div>
        <div class="spacer"></div>
        <a class="btn btn-ghost" href="logs.php">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>
            Back to Logs
        </a>
        <a class="btn" href="download.php?file=<?= urlencode($_GET["file"] ?? "") ?>">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
            Download
        </a>
    </div>

    <div class="viewer">
        <div class="viewer-bar">
            <span class="dots"><i style="background:#f87171"></i><i style="background:#fbbf24"></i><i style="background:#34d399"></i></span>
            <span><?= htmlspecialchars($filename) ?></span>
        </div>
        <pre><?= $content ?></pre>
    </div>
</div>

</body>
</html>
