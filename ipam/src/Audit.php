<?php
declare(strict_types=1);

namespace DarkVeda;

final class Audit
{
    public static function log(string $action, string $entityType, ?string $entityId = null, ?string $details = null): void
    {
        try {
            Database::exec(
                'INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address)
                 VALUES (?, ?, ?, ?, ?, ?)',
                [
                    Auth::id(),
                    $action,
                    $entityType,
                    $entityId,
                    $details,
                    $_SERVER['REMOTE_ADDR'] ?? null,
                ]
            );
        } catch (\Throwable) {
            // Auditing must never break the request.
        }
    }
}
