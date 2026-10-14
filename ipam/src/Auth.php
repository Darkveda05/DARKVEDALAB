<?php
declare(strict_types=1);

namespace DarkVeda;

final class Auth
{
    public static function attempt(string $username, string $password): bool
    {
        $user = Database::one(
            'SELECT u.*, r.name AS role_name FROM users u
             JOIN roles r ON r.id = u.role_id
             WHERE u.username = ? AND u.is_active = 1',
            [$username]
        );
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return false;
        }

        session_regenerate_id(true);
        $_SESSION['user'] = [
            'id'        => (int)$user['id'],
            'username'  => $user['username'],
            'full_name' => $user['full_name'],
            'role'      => $user['role_name'],
            'role_id'   => (int)$user['role_id'],
        ];
        $_SESSION['permissions'] = array_column(Database::q(
            'SELECT p.name FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             WHERE rp.role_id = ?',
            [$user['role_id']]
        ), 'name');

        Database::exec('UPDATE users SET last_login_at = NOW() WHERE id = ?', [$user['id']]);
        Audit::log('login', 'user', (string)$user['id']);
        return true;
    }

    public static function logout(): void
    {
        if (self::check()) {
            Audit::log('logout', 'user', (string)self::id());
        }
        $_SESSION = [];
        session_destroy();
    }

    public static function check(): bool
    {
        return isset($_SESSION['user']);
    }

    public static function user(): ?array
    {
        return $_SESSION['user'] ?? null;
    }

    public static function id(): ?int
    {
        return $_SESSION['user']['id'] ?? null;
    }

    public static function can(string $permission): bool
    {
        return in_array($permission, $_SESSION['permissions'] ?? [], true);
    }

    /** Gate a page: requires login + optional permission. */
    public static function requirePermission(?string $permission = null): void
    {
        if (!self::check()) {
            App::redirect('/?page=login');
        }
        if ($permission !== null && !self::can($permission)) {
            http_response_code(403);
            App::render('403');
            exit;
        }
    }

    // ---------------- CSRF ----------------

    public static function csrfToken(): string
    {
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public static function csrfField(): string
    {
        return '<input type="hidden" name="_csrf" value="' . self::csrfToken() . '">';
    }

    public static function verifyCsrf(): void
    {
        $sent = $_POST['_csrf'] ?? '';
        if (!hash_equals($_SESSION['csrf'] ?? '', $sent)) {
            http_response_code(419);
            exit('CSRF token mismatch.');
        }
    }

    // ---------------- API tokens ----------------

    /** Validate "Authorization: Bearer <token>" header; returns user row or null. */
    public static function apiUser(): ?array
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/^Bearer\s+(\S+)$/', $header, $m)) {
            return null;
        }
        $hash = hash('sha256', $m[1]);
        $row = Database::one(
            'SELECT u.id, u.username, u.role_id FROM api_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND u.is_active = 1',
            [$hash]
        );
        if ($row) {
            Database::exec('UPDATE api_tokens SET last_used = NOW() WHERE token_hash = ?', [$hash]);
        }
        return $row;
    }
}
