<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    die("Unauthorized");
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Invalid request");
}

/* ==================================================
   PORTABLE PROJECT PATH (NO HARD-CODED SERVER PATH)
================================================== */
$baseDir = dirname(__DIR__); // MVNBC_Dashboard root

$configFile = $baseDir . "/config/devices.conf";
$logFile    = $baseDir . "/logs/audit.log";

/* ==================================================
   INPUT
================================================== */
$data = $_POST['data'] ?? '';

if (trim($data) === '') {
    die("Empty config not allowed");
}

/* ==================================================
   NORMALIZE INPUT
================================================== */
$data = str_replace("\r\n", "\n", $data);
$lines = explode("\n", $data);

$clean = [];

foreach ($lines as $line) {

    $line = trim($line);
    if ($line === '') continue;

    /* Remove unwanted characters (INCLUDING %) */
    $line = str_replace('%', '', $line);
    $line = preg_replace('/[^a-zA-Z0-9.,@:_\\-]/', '', $line);

    $parts = explode(',', $line);
    if (count($parts) < 4) continue;

    $vendor = strtolower(trim($parts[0]));
    $ip     = trim($parts[1]);
    $user   = trim($parts[2]);
    $pass   = trim($parts[3]);
    $enable = $parts[4] ?? '';

    /* Vendor whitelist */
    $allowedVendors = ['cisco','ciscoasa','mikrotik','arista','h3c','aruba'];
    if (!in_array($vendor, $allowedVendors)) continue;

    /* IP validation */
    if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;

    /* rebuild clean line */
    $cleanLine = $vendor . "," . $ip . "," . $user . "," . $pass;

    if (!empty($enable)) {
        $cleanLine .= "," . $enable;
    }

    $clean[] = $cleanLine;
}

/* ==================================================
   SAFETY CHECK
================================================== */
if (empty($clean)) {
    die("No valid configuration data to save");
}

/* ==================================================
   WRITE FILE
================================================== */
$result = file_put_contents($configFile, implode("\n", $clean));

if ($result === false) {
    die("Write failed - check permissions or path");
}

/* ==================================================
   AUDIT LOG
================================================== */
file_put_contents(
    $logFile,
    date("Y-m-d H:i:s") . " - devices.conf updated\n",
    FILE_APPEND
);

/* ==================================================
   REDIRECT
================================================== */
header("Location: ../modules/config.php?success=1");
exit;
?>