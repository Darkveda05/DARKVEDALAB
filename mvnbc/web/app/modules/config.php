<?php
session_start();
if (!isset($_SESSION['logged_in'])) {
    header("Location: ../../login.php");
    exit;
}

require_once __DIR__ . '/../includes/layout.php';

/* ==================================================
   PATHS
================================================== */
$BASE_DIR   = realpath(__DIR__ . "/../../..");
$configFile = $BASE_DIR . "/config/devices.conf";
$logFile    = $BASE_DIR . "/logs/audit.log";

/* Vendors supported by the backup engine (matches templates/*.exp) */
$ALLOWED_VENDORS = ['arista','aruba','arubacx','cisco','ciscoasa','fortigate','h3c','h3c_1920','juniper','mikrotik'];

$msg = "";
$ok  = false;

/* ==================================================
   HELPERS
================================================== */
function load_devices($file) {
    $rows = [];
    $raw = @file_get_contents($file);
    if ($raw === false) return $rows;
    foreach (explode("\n", str_replace("\r\n", "\n", $raw)) as $i => $line) {
        $line = trim($line);
        if ($line === "" || $line[0] === "#") continue;
        $p = explode(",", $line);
        if (count($p) < 4) continue;
        $rows[] = [
            'vendor' => trim($p[0]),
            'ip'     => trim($p[1]),
            'user'   => trim($p[2]),
            'pass'   => trim($p[3]),
            'enable' => isset($p[4]) ? trim($p[4]) : '',
        ];
    }
    return $rows;
}

function write_devices($file, $rows, $logFile) {
    $lines = [];
    foreach ($rows as $r) {
        $line = $r['vendor'] . "," . $r['ip'] . "," . $r['user'] . "," . $r['pass'];
        if ($r['enable'] !== '') $line .= "," . $r['enable'];
        $lines[] = $line;
    }
    $res = file_put_contents($file, implode("\n", $lines) . (count($lines) ? "\n" : ""), LOCK_EX);
    if ($res !== false) {
        @file_put_contents($logFile, date("Y-m-d H:i:s") . " - devices.conf updated\n", FILE_APPEND);
    }
    return $res !== false;
}

/* Reject characters that could break the CSV line; keep typical credential chars */
function clean_field($s) {
    $s = trim($s);
    $s = str_replace(["\n", "\r", ","], "", $s);  // never allow newlines or commas in a field
    return $s;
}

/* ==================================================
   POST: ADD or DELETE device
================================================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $action = $_POST['action'] ?? '';
    $rows   = load_devices($configFile);

    if ($action === 'add') {
        $vendor = strtolower(clean_field($_POST['vendor'] ?? ''));
        $ip     = clean_field($_POST['ip'] ?? '');
        $user   = clean_field($_POST['username'] ?? '');
        $pass   = clean_field($_POST['password'] ?? '');
        $enable = clean_field($_POST['enable'] ?? '');

        if (!in_array($vendor, $ALLOWED_VENDORS, true)) {
            $msg = "Please choose a supported vendor.";
        } elseif (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $msg = "“" . htmlspecialchars($ip) . "” is not a valid IP address.";
        } elseif ($user === '' || $pass === '') {
            $msg = "Username and password are required.";
        } else {
            // prevent duplicate vendor+ip entries
            $dup = false;
            foreach ($rows as $r) {
                if (strtolower($r['vendor']) === $vendor && $r['ip'] === $ip) { $dup = true; break; }
            }
            if ($dup) {
                $msg = "A device with this vendor and IP already exists.";
            } else {
                $rows[] = ['vendor'=>$vendor,'ip'=>$ip,'user'=>$user,'pass'=>$pass,'enable'=>$enable];
                if (write_devices($configFile, $rows, $logFile)) {
                    $msg = "Device $vendor ($ip) added.";
                    $ok = true;
                } else {
                    $msg = "Could not write devices.conf. Check file permissions.";
                }
            }
        }
    } elseif ($action === 'delete') {
        $dvendor = strtolower(trim($_POST['d_vendor'] ?? ''));
        $dip     = trim($_POST['d_ip'] ?? '');
        $before  = count($rows);
        $rows = array_values(array_filter($rows, function($r) use ($dvendor,$dip) {
            return !(strtolower($r['vendor']) === $dvendor && $r['ip'] === $dip);
        }));
        if (count($rows) < $before) {
            if (write_devices($configFile, $rows, $logFile)) {
                $msg = "Device removed.";
                $ok = true;
            } else {
                $msg = "Could not write devices.conf. Check file permissions.";
            }
        } else {
            $msg = "Device not found.";
        }
    }
}

/* reload after any change */
$rows = load_devices($configFile);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Devices · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('devices', 'Devices', 'Manage the device backup inventory', '../../'); ?>

<?php if ($msg): ?>
    <div class="flash <?= $ok ? 'success' : 'error' ?>">
        <?= mvnbc_icon($ok ? 'check' : 'alert') ?>
        <span><?= $msg ?></span>
    </div>
<?php endif; ?>

<!-- ===== DEVICE INVENTORY ===== -->
<div class="panel">
    <div class="panel-head">
        <h2>Device Inventory</h2>
        <span class="count-chip"><?= count($rows) ?> device<?= count($rows) === 1 ? '' : 's' ?></span>
    </div>

    <?php if (empty($rows)): ?>
        <div class="empty"><?= mvnbc_icon('devices') ?><h3>No devices configured</h3><p>Add your first device using the form below.</p></div>
    <?php else: ?>
    <div class="table-wrap">
    <table class="data">
        <thead><tr><th>Vendor</th><th>IP Address</th><th>Username</th><th>Credentials</th><th>Enable</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($rows as $r): ?>
            <tr>
                <td class="file-name"><?= htmlspecialchars(strtoupper($r['vendor'])) ?></td>
                <td class="mono"><?= htmlspecialchars($r['ip']) ?></td>
                <td class="mono"><?= htmlspecialchars($r['user']) ?></td>
                <td><span class="pill ok">stored</span></td>
                <td><?= $r['enable'] !== '' ? '<span class="pill ok">set</span>' : '<span class="pill muted">—</span>' ?></td>
                <td style="text-align:right;">
                    <form method="POST" onsubmit="return confirm('Remove <?= htmlspecialchars(addslashes(strtoupper($r['vendor']) . ' ' . $r['ip'])) ?> from devices.conf?');" style="margin:0;">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="d_vendor" value="<?= htmlspecialchars($r['vendor']) ?>">
                        <input type="hidden" name="d_ip" value="<?= htmlspecialchars($r['ip']) ?>">
                        <button type="submit" class="btn btn-danger btn-sm"><?= mvnbc_icon('trash') ?> Remove</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

<!-- ===== ADD DEVICE ===== -->
<div class="panel">
    <div class="panel-head"><h2>Add Device</h2></div>

    <form method="POST">
        <input type="hidden" name="action" value="add">
        <div class="form-grid">
            <div>
                <label class="field-label">Vendor</label>
                <select name="vendor" required>
                    <option value="" disabled selected>Select vendor…</option>
                    <?php foreach ($ALLOWED_VENDORS as $v): ?>
                        <option value="<?= $v ?>"><?= strtoupper($v) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="field-label">IP Address</label>
                <input class="input mono" type="text" name="ip" placeholder="192.0.2.10" required>
            </div>
            <div>
                <label class="field-label">Username</label>
                <input class="input mono" type="text" name="username" placeholder="admin" required autocomplete="off">
            </div>
            <div>
                <label class="field-label">Password</label>
                <input class="input mono" type="password" name="password" placeholder="••••••••" required autocomplete="new-password">
            </div>
            <div>
                <label class="field-label">Enable password <span class="opt">(optional)</span></label>
                <input class="input mono" type="password" name="enable" placeholder="leave blank if unused" autocomplete="new-password">
            </div>
        </div>
        <div class="btn-row">
            <button type="submit" class="btn btn-primary"><?= mvnbc_icon('save') ?> Add device</button>
        </div>
    </form>

    <div class="note">
        <p style="margin:0;"><?= mvnbc_icon('shield') ?> New devices are written to <code>config/devices.conf</code> and picked up on the next <code>MVNBC.sh</code> backup run.</p>
    </div>
</div>

<?php mvnbc_shell_close(); ?>
</body>
</html>
