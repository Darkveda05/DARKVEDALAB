<?php
declare(strict_types=1);

namespace DarkVeda;

final class App
{
    private static ?array $config = null;

    public static function config(): array
    {
        if (self::$config === null) {
            self::$config = require self::configFile();
        }
        return self::$config;
    }

    /**
     * Locate the active configuration file.
     *
     * A hand-written config/config.php always wins. When it is absent — the
     * normal case for a fresh clone or a container — we fall back to
     * config/config.example.php, which reads every value from environment
     * variables. That makes `docker compose up` work with nothing but the
     * variables in .env, and keeps real credentials out of the repo and image.
     */
    public static function configFile(): string
    {
        $dir = dirname(__DIR__) . '/config';
        $local = $dir . '/config.php';
        if (is_file($local)) {
            return $local;
        }
        $example = $dir . '/config.example.php';
        if (is_file($example)) {
            return $example;
        }
        throw new \RuntimeException(
            'No configuration found. Expected config/config.php or config/config.example.php.'
        );
    }

    public static function boot(): void
    {
        $cfg = self::config();
        date_default_timezone_set($cfg['app']['timezone']);

        if ($cfg['app']['debug']) {
            ini_set('display_errors', '1');
            error_reporting(E_ALL);
        } else {
            ini_set('display_errors', '0');
        }

        session_name($cfg['security']['session_name']);
        session_set_cookie_params([
            'lifetime' => $cfg['security']['session_lifetime'],
            'httponly' => true,
            'samesite' => 'Lax',
            'secure'   => !empty($_SERVER['HTTPS']),
        ]);
        session_start();
    }

    /**
     * Render a page inside the main layout.
     *
     * The paths are held in names prefixed with __dv so that a page defining
     * a common variable (e.g. $base or $page) cannot clobber the renderer's
     * own state and break the includes that follow it.
     */
    public static function render(string $page, array $vars = []): void
    {
        $__dvBase = dirname(__DIR__);
        $__dvPage = $page;
        extract($vars, EXTR_SKIP);
        require $__dvBase . '/partials/header.php';
        require $__dvBase . '/pages/' . $__dvPage . '.php';
        require $__dvBase . '/partials/footer.php';
    }

    public static function redirect(string $path): never
    {
        header('Location: ' . $path);
        exit;
    }

    public static function flash(string $type, string $message): void
    {
        $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
    }

    public static function takeFlashes(): array
    {
        $f = $_SESSION['flash'] ?? [];
        unset($_SESSION['flash']);
        return $f;
    }
}

/** HTML-escape shorthand. */
function e(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}
