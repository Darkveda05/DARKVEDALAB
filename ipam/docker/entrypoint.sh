#!/bin/sh
# ---------------------------------------------------------------
# DarkVeda IPAM container bootstrap
#
#  1. wait for the database
#  2. import the schema on first run
#  3. apply any pending upgrade scripts
#  4. set the admin password from ADMIN_PASSWORD when supplied
# ---------------------------------------------------------------
set -e

# App root: defaults to the image path, overridable for local testing.
APP_DIR="${APP_DIR:-/var/www/html}"

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-darkveda_ipam}"
DB_USER="${DB_USER:-darkveda}"
DB_PASS="${DB_PASS:-}"

log() { echo "[darkveda] $*"; }

# --- 1. wait for the database ---------------------------------
log "waiting for ${DB_HOST}:${DB_PORT} ..."
i=0
until mariadb -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e 'SELECT 1' >/dev/null 2>&1 \
   || mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e 'SELECT 1' >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        log "database did not become ready in time — starting anyway"
        break
    fi
    sleep 2
done

MYSQL="mysql -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASS $DB_NAME"
command -v mariadb >/dev/null 2>&1 && MYSQL="mariadb -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASS $DB_NAME"

# --- 2. first-run schema import -------------------------------
TABLES=$($MYSQL -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME'" 2>/dev/null || echo 0)
if [ "${TABLES:-0}" -lt 5 ]; then
    log "empty database detected — importing schema"
    if [ ! -f "$APP_DIR/database/schema.sql" ]; then
        log "ERROR: $APP_DIR/database/schema.sql not found — cannot bootstrap"
        exit 1
    fi
    # the shipped schema creates and selects its own database; the container
    # already has one, so drop those statements (CREATE DATABASE spans 2 lines)
    sed -e '/^CREATE DATABASE/,/;/d' -e '/^USE /d' "$APP_DIR/database/schema.sql" | $MYSQL \
        && log "schema imported" \
        || { log "ERROR: schema import failed"; exit 1; }
else
    log "found $TABLES tables — skipping schema import"
fi

# --- 3. upgrade scripts (idempotent) --------------------------
for f in "$APP_DIR"/database/upgrade_*.sql; do
    [ -e "$f" ] || continue
    log "applying $(basename "$f")"
    $MYSQL < "$f" >/dev/null 2>&1 || log "  (already applied or partially skipped)"
done

# --- 4. admin password ----------------------------------------
if [ -n "${ADMIN_PASSWORD:-}" ]; then
    log "setting the admin password from ADMIN_PASSWORD"
    php -r '
        $p = getenv("ADMIN_PASSWORD");
        if (strlen($p) < 10) { fwrite(STDERR, "[darkveda] ADMIN_PASSWORD must be at least 10 characters — skipped\n"); exit(0); }
        $h = password_hash($p, PASSWORD_BCRYPT, ["cost" => 12]);
        $pdo = new PDO(sprintf("mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
            getenv("DB_HOST") ?: "db", (int)(getenv("DB_PORT") ?: 3306), getenv("DB_NAME") ?: "darkveda_ipam"),
            getenv("DB_USER") ?: "darkveda", getenv("DB_PASS") ?: "");
        $st = $pdo->prepare("UPDATE users SET password_hash = ?, is_active = 1 WHERE username = \"admin\"");
        $st->execute([$h]);
    ' || log "  could not set the admin password"
fi

chown -R www-data:www-data "$APP_DIR"/public/uploads 2>/dev/null || true

log "ready"
exec "$@"
