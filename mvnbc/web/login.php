<?php
session_start();

if (!empty($_SESSION['logged_in'])) {
    header("Location: index.php");
    exit;
}

$error = "";

/* PASSWORD FILE */
$BASE_DIR = realpath(__DIR__ . "/..");
$passwordFile = $BASE_DIR . "/config/password.txt";

/* READ PASSWORD FROM FILE */
if (!file_exists($passwordFile)) {
    die("Password file not found!");
}

$valid_pass = trim(file_get_contents($passwordFile));

$valid_user = "admin"; // still fixed username

/* Detect whether the stored password is a bcrypt/argon hash or legacy plaintext */
function mvnbc_is_hash($s) {
    return is_string($s) && (strncmp($s, '$2y$', 4) === 0
        || strncmp($s, '$argon2', 7) === 0
        || strncmp($s, '$2a$', 4) === 0);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    /* simple brute force protection */
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    if ($_SESSION['login_attempts'] >= 5) {
        $error = "Too many failed attempts. Try again later.";
    } else {

        /* Verify against a hash when present; fall back to plaintext compare for the
           legacy file, and transparently upgrade it to a hash on success. */
        if (mvnbc_is_hash($valid_pass)) {
            $passOk = password_verify($password, $valid_pass);
        } else {
            $passOk = hash_equals($valid_pass, $password);
            if ($passOk) {
                // upgrade legacy plaintext store to a bcrypt hash
                @file_put_contents($passwordFile, password_hash($password, PASSWORD_DEFAULT), LOCK_EX);
            }
        }

        if ($username === $valid_user && $passOk) {

            session_regenerate_id(true);

            $_SESSION['logged_in'] = true;
            $_SESSION['username'] = $username;
            $_SESSION['last_activity'] = time();

            $_SESSION['login_attempts'] = 0;

            header("Location: index.php");
            exit;

        } else {
            $_SESSION['login_attempts']++;
            $error = "Invalid username or password";
        }
    }
}

if (isset($_GET['error']) && $_GET['error'] === 'session' && $error === '') {
    $error = "Your session expired. Please sign in again.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · MVNBC</title>
<link rel="stylesheet" href="assets/style.css?v=6">
</head>
<body>

<div class="login-screen">
    <div class="login-card">
        <img src="img/mvnbc.png" class="logo" alt="MVNBC">
        <h1>MVNBC Backup Console</h1>
        <div class="tagline">Multivendor Network Configuration Backups</div>

        <?php if ($error): ?>
            <div class="login-error">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
                <span><?= htmlspecialchars($error) ?></span>
            </div>
        <?php endif; ?>

        <form method="POST">
            <div class="field">
                <label class="field-label">Username</label>
                <input type="text" name="username" placeholder="admin" required autofocus>
            </div>
            <div class="field">
                <label class="field-label">Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit">Sign in</button>
        </form>

        <div class="login-foot">Authorized network operators only</div>
    </div>
</div>

</body>
</html>
