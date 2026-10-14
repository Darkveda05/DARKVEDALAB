<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    die("Unauthorized");
}

$allowedDirs = [
    realpath(__DIR__ . "/../backups"),
    realpath(__DIR__ . "/../logs")
];

$file = realpath($_GET['file'] ?? '');

$valid = false;

foreach ($allowedDirs as $dir) {

    if ($file && strpos($file, $dir) === 0) {
        $valid = true;
    }
}

if (!$valid || !file_exists($file)) {
    die("Invalid file");
}

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($file) . '"');
header('Content-Length: ' . filesize($file));

readfile($file);

exit;