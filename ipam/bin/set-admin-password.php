<?php
declare(strict_types=1);

/**
 * DarkVeda IPAM — set/reset the admin password.
 *
 *   php bin/set-admin-password.php 'YourNewPassword'
 *
 * Run inside the app container:
 *   docker compose exec app php bin/set-admin-password.php 'YourNewPassword'
 */

require dirname(__DIR__) . '/src/App.php';
require dirname(__DIR__) . '/src/Database.php';

use DarkVeda\{App, Database};

if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

$password = $argv[1] ?? '';
if (strlen($password) < 10) {
    fwrite(STDERR, "Usage: php bin/set-admin-password.php '<password, min 10 chars>'\n");
    exit(1);
}

App::config();
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => App::config()['security']['bcrypt_cost']]);
$count = Database::exec('UPDATE users SET password_hash = ? WHERE username = ?', [$hash, 'admin']);

echo $count > 0
    ? "Admin password updated.\n"
    : "No 'admin' user found — has the schema been imported?\n";
