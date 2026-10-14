<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header("Location: ../../login.php");
    exit;
}

$msg = "";
$ok  = false;

$BASE_DIR = realpath(__DIR__ . "/../../..");
$passwordFile = $BASE_DIR . "/config/password.txt";

/* Detect whether the stored password is a bcrypt/argon hash or legacy plaintext */
function mvnbc_is_hash($s) {
    return is_string($s) && (strncmp($s, '$2y$', 4) === 0
        || strncmp($s, '$argon2', 7) === 0
        || strncmp($s, '$2a$', 4) === 0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $old = isset($_POST['old_password']) ? $_POST['old_password'] : '';
    $new = isset($_POST['new_password']) ? $_POST['new_password'] : '';

    $current = trim(file_get_contents($passwordFile));

    /* Verify the current password against a hash, or plaintext for the legacy file */
    $oldOk = mvnbc_is_hash($current)
        ? password_verify($old, $current)
        : hash_equals($current, $old);

    if (!$oldOk) {
        $msg = "Current password is incorrect.";
    } elseif (trim($new) === '') {
        $msg = "New password cannot be empty.";
    } else {
        /* Always store the new password as a bcrypt hash, never plaintext */
        $hash = password_hash($new, PASSWORD_DEFAULT);
        if (file_put_contents($passwordFile, $hash, LOCK_EX) !== false) {
            $msg = "Password updated successfully.";
            $ok  = true;
        } else {
            $msg = "Could not write the password file. Check permissions.";
        }
    }
}

require_once __DIR__ . '/../includes/layout.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security · MVNBC</title>
<link rel="stylesheet" href="../../assets/style.css?v=6">
</head>
<body>

<?php mvnbc_shell_open('settings', 'Security', 'Manage the console sign-in password', '../../'); ?>

<?php if ($msg): ?>
    <div class="flash <?= $ok ? 'success' : 'error' ?>">
        <?= mvnbc_icon($ok ? 'check' : 'alert') ?>
        <span><?= htmlspecialchars($msg) ?></span>
    </div>
<?php endif; ?>

<div class="panel" style="max-width:520px;">
    <div class="panel-head"><h2>Change Password</h2></div>

    <form method="POST">
        <div style="margin-bottom:14px;">
            <label class="field-label">Current password</label>
            <input class="input" type="password" name="old_password" placeholder="••••••••" required>
        </div>
        <div style="margin-bottom:18px;">
            <label class="field-label">New password</label>
            <input class="input" type="password" name="new_password" placeholder="Choose a strong password" required>
        </div>
        <button type="submit" class="btn btn-primary"><?= mvnbc_icon('save') ?> Update password</button>
    </form>

    <div class="note">
        <p style="margin:0;"><?= mvnbc_icon('shield') ?> The username remains <code>admin</code>. The password is stored on the server as a one-way bcrypt hash (never plaintext) and applies to every operator using this console.</p>
    </div>
</div>

<?php mvnbc_shell_close(); ?>
</body>
</html>
