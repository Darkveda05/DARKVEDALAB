<?php
session_start();
if (!isset($_SESSION['logged_in'])) {
    header("Location: ../../login.php");
    exit;
}

require_once __DIR__ . '/../includes/layout.php';
require_once __DIR__ . '/../includes/settings.php';
require_once __DIR__ . '/../includes/notify.php';

$settings = mvnbc_load_settings();
$msg = ""; $ok = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'save') {
        $settings['alerts']['notify_on'] = in_array($_POST['notify_on'] ?? 'failure', ['failure','always','never'], true)
            ? $_POST['notify_on'] : 'failure';

        $settings['email']['enabled']     = isset($_POST['email_enabled']);
        $settings['email']['smtp_host']   = trim($_POST['smtp_host'] ?? '');
        $settings['email']['smtp_port']   = (int)($_POST['smtp_port'] ?? 587);
        $settings['email']['smtp_secure'] = in_array($_POST['smtp_secure'] ?? 'tls', ['tls','ssl','none'], true)
            ? $_POST['smtp_secure'] : 'tls';
        $settings['email']['username']    = trim($_POST['email_username'] ?? '');
        // keep existing password if the field is left blank
        $newPass = $_POST['email_password'] ?? '';
        if ($newPass !== '') $settings['email']['password'] = $newPass;
        $settings['email']['from']        = trim($_POST['email_from'] ?? '');
        $settings['email']['to']          = trim($_POST['email_to'] ?? '');

        $settings['telegram']['enabled']   = isset($_POST['tg_enabled']);
        $newToken = trim($_POST['tg_token'] ?? '');
        if ($newToken !== '') $settings['telegram']['bot_token'] = $newToken;
        $settings['telegram']['chat_id']   = trim($_POST['tg_chat'] ?? '');

        if (mvnbc_save_settings($settings)) {
            $msg = "Alert settings saved."; $ok = true;
        } else {
            $msg = "Could not write settings.json. Check file permissions.";
        }
        $settings = mvnbc_load_settings();

    } elseif ($action === 'test_email') {
        [$ok, $m] = mvnbc_send_email($settings['email'],
            "MVNBC test alert",
            "This is a test message from your MVNBC Backup Console.\nIf you can read this, email alerts are working.");
        $msg = $m;

    } elseif ($action === 'test_telegram') {
        $tg = $settings['telegram'];
        [$ok, $m] = mvnbc_send_telegram($tg['bot_token'], $tg['chat_id'],
            "<b>MVNBC test alert</b>\n\nThis is a test message from your MVNBC Backup Console.\nIf you can read this, Telegram alerts are working.");
        $msg = $m;
    }
}

$e = $settings['email'];
$t = $settings['telegram'];
$hasEmailPass = $e['password'] !== '';
$hasTgToken   = $t['bot_token'] !== '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Alerts · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('alerts', 'Alerts', 'Email and Telegram notifications for backup runs', '../../'); ?>

<?php if ($msg): ?>
    <div class="flash <?= $ok ? 'success' : 'error' ?>">
        <?= mvnbc_icon($ok ? 'check' : 'alert') ?>
        <span><?= htmlspecialchars($msg) ?></span>
    </div>
<?php endif; ?>

<form method="POST">
<input type="hidden" name="action" value="save">

<!-- WHEN TO NOTIFY -->
<div class="panel">
    <div class="panel-head"><h2>When to notify</h2></div>
    <div class="seg-field">
        <label class="radio-tile">
            <input type="radio" name="notify_on" value="failure" <?= $settings['alerts']['notify_on']==='failure'?'checked':'' ?>>
            <span><strong>On failure</strong><small>Alert only when one or more backups fail</small></span>
        </label>
        <label class="radio-tile">
            <input type="radio" name="notify_on" value="always" <?= $settings['alerts']['notify_on']==='always'?'checked':'' ?>>
            <span><strong>Every run</strong><small>Send a summary after each backup run</small></span>
        </label>
        <label class="radio-tile">
            <input type="radio" name="notify_on" value="never" <?= $settings['alerts']['notify_on']==='never'?'checked':'' ?>>
            <span><strong>Never</strong><small>Disable automatic alerts</small></span>
        </label>
    </div>
</div>

<!-- EMAIL -->
<div class="panel">
    <div class="panel-head">
        <h2>Email (SMTP)</h2>
        <label class="switch">
            <input type="checkbox" name="email_enabled" <?= $e['enabled']?'checked':'' ?>>
            <span class="switch-track"></span><span class="switch-label">Enabled</span>
        </label>
    </div>
    <div class="form-grid">
        <div>
            <label class="field-label">SMTP host</label>
            <input class="input mono" type="text" name="smtp_host" value="<?= htmlspecialchars($e['smtp_host']) ?>" placeholder="smtp.gmail.com">
        </div>
        <div>
            <label class="field-label">Port</label>
            <input class="input mono" type="number" name="smtp_port" value="<?= htmlspecialchars($e['smtp_port']) ?>" placeholder="587">
        </div>
        <div>
            <label class="field-label">Encryption</label>
            <select name="smtp_secure">
                <option value="tls"  <?= $e['smtp_secure']==='tls'?'selected':'' ?>>STARTTLS (587)</option>
                <option value="ssl"  <?= $e['smtp_secure']==='ssl'?'selected':'' ?>>SSL/TLS (465)</option>
                <option value="none" <?= $e['smtp_secure']==='none'?'selected':'' ?>>None (25)</option>
            </select>
        </div>
        <div>
            <label class="field-label">Username</label>
            <input class="input mono" type="text" name="email_username" value="<?= htmlspecialchars($e['username']) ?>" placeholder="you@example.com" autocomplete="off">
        </div>
        <div>
            <label class="field-label">Password <span class="opt"><?= $hasEmailPass ? '(saved — leave blank to keep)' : '' ?></span></label>
            <input class="input mono" type="password" name="email_password" placeholder="<?= $hasEmailPass ? '••••••••' : 'app password' ?>" autocomplete="new-password">
        </div>
        <div>
            <label class="field-label">From address</label>
            <input class="input mono" type="text" name="email_from" value="<?= htmlspecialchars($e['from']) ?>" placeholder="alerts@example.com">
        </div>
        <div class="span-2">
            <label class="field-label">Recipients <span class="opt">(comma separated)</span></label>
            <input class="input mono" type="text" name="email_to" value="<?= htmlspecialchars($e['to']) ?>" placeholder="noc@example.com, oncall@example.com">
        </div>
    </div>
    <div class="btn-row">
        <button type="submit" class="btn btn-primary"><?= mvnbc_icon('save') ?> Save settings</button>
        <button type="submit" name="action" value="test_email" class="btn btn-ghost"><?= mvnbc_icon('alert') ?> Send test email</button>
    </div>
</div>

<!-- TELEGRAM -->
<div class="panel">
    <div class="panel-head">
        <h2>Telegram</h2>
        <label class="switch">
            <input type="checkbox" name="tg_enabled" <?= $t['enabled']?'checked':'' ?>>
            <span class="switch-track"></span><span class="switch-label">Enabled</span>
        </label>
    </div>
    <div class="form-grid">
        <div class="span-2">
            <label class="field-label">Bot token <span class="opt"><?= $hasTgToken ? '(saved — leave blank to keep)' : '' ?></span></label>
            <input class="input mono" type="password" name="tg_token" placeholder="<?= $hasTgToken ? '••••••••' : '123456:ABC-DEF...' ?>" autocomplete="new-password">
        </div>
        <div class="span-2">
            <label class="field-label">Chat ID</label>
            <input class="input mono" type="text" name="tg_chat" value="<?= htmlspecialchars($t['chat_id']) ?>" placeholder="-1001234567890">
        </div>
    </div>
    <div class="btn-row">
        <button type="submit" class="btn btn-primary"><?= mvnbc_icon('save') ?> Save settings</button>
        <button type="submit" name="action" value="test_telegram" class="btn btn-ghost"><?= mvnbc_icon('alert') ?> Send test message</button>
    </div>
    <div class="note">
        <p style="margin:0;"><?= mvnbc_icon('shield') ?> Create a bot with <code>@BotFather</code> to get a token. To find your chat ID, message the bot, then check <code>https://api.telegram.org/bot&lt;token&gt;/getUpdates</code>. Credentials are stored in <code>config/settings.json</code> (chmod 600).</p>
    </div>
</div>

</form>

<?php mvnbc_shell_close(); ?>
</body>
</html>
