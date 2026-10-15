#!/bin/bash
# Copyright (c) 2026, Darkveda All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

umask 002

# ==================================================
# ROBUST PATH (web server / cron run with a minimal env)
# When this script is launched by PHP (nginx/php-fpm) or cron, PATH is
# often stripped down to /usr/bin:/bin, so tools like `expect`, `ssh`,
# and `crontab` are "command not found" even though they work in an
# interactive shell. Prepend the common locations so they resolve.
# ==================================================
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export TZ="Asia/Kuala_Lumpur"

# ==================================================
# CRON-PROOF BASE PATH (NO PWD DEPENDENCY)
# ==================================================
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

BASE_DIR="$SCRIPT_DIR"

# ==================================================
# SSH defaults (LOCAL LAN mode — no WireGuard needed)
# MVNBC just opens a plain SSH session to the IP in devices.conf.
# If that IP is reachable on your LAN, no wg0/tunnel is required.
# Override per run: MVNBC_SSH_PORT=2222 MVNBC_SSH_TIMEOUT=15 ./MVNBC.sh --auto
# Per device:  mikrotik,192.168.88.1,admin,pass        (port 22)
#              mikrotik,192.168.88.1:2222,admin,pass   (inline port)
#              mikrotik,192.168.88.1,admin,pass,,2222  (6th field)
# ==================================================
DEFAULT_SSH_PORT="${MVNBC_SSH_PORT:-22}"
SSH_TIMEOUT="${MVNBC_SSH_TIMEOUT:-15}"

# ==================================================
# DEPENDENCY CHECK — locate `expect` (the #1 cause of "all failed"
# when the backup is launched from the web UI under a minimal PATH)
# ==================================================
EXPECT_BIN="$(command -v expect 2>/dev/null)"

CONFIG_FILE="$BASE_DIR/config/devices.conf"
BACKUP_DIR="$BASE_DIR/backups"
TEMPLATE_DIR="$BASE_DIR/templates"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$BACKUP_DIR" "$LOG_DIR"

# ==================================================
# GLOBAL RUN LOG (CRON SAFE)
# ==================================================
RUN_ID=$(date +%Y%m%d_%H%M%S)
RUN_LOG="$LOG_DIR/run_${RUN_ID}.log"

exec > >(tee -a "$RUN_LOG") 2>&1
# The `tee` above runs asynchronously (process substitution). Without waiting for
# it, the shell can exit before tee flushes, TRUNCATING the tail of the log
# (this is why some run_*.log files cut off mid-line). Capture tee's PID and,
# on exit, close our stdout/stderr so tee sees EOF, then wait for it to finish.
# (Ported from MVNBC_Dashboard original.)
TEE_PID=$!
trap 'exec 1>&- 2>&-; [ -n "$TEE_PID" ] && wait "$TEE_PID" 2>/dev/null' EXIT

echo "======================================"
echo " Multi-Vendor Auto Backup Engine"
echo "======================================"
echo "[INFO] RUN ID: $RUN_ID"
echo "[INFO] BASE DIR: $BASE_DIR"
echo "[INFO] STARTED"
echo ""


# ==================================================
# BACKUP VALIDATION
# ==================================================
validate_backup() {

    local vendor="$1"
    local file="$2"

    [[ ! -s "$file" ]] && return 1

    case "$vendor" in

        cisco)
            grep -Eq \
            "Current configuration|Building configuration|^hostname " \
            "$file"
            ;;

        ciscoasa)
            grep -Eq \
            "^ASA Version|^hostname " \
            "$file"
            ;;

        mikrotik)
            grep -qi "RouterOS" "$file" &&
			grep -Eq "/interface|/ip |/system " "$file"
            ;;

        h3c)
            grep -Eq \
            "^sysname |System View|display cu|display current-configuration" \
            "$file"
            ;;
			
	     h3c_1920)
            grep -Eq \
            "^sysname |System View|display cu|display current-configuration" \
            "$file"
            ;;

        arista)
            grep -Eq \
            "^hostname |^! device:" \
            "$file"
            ;;

        aruba)
            grep -Eq \
            "^hostname |Current configuration" \
            "$file"
            ;;
			
		fortigate)
			grep -Eq \
			"^config system|^config firewall|^set hostname|^end$" \
			"$file"
			;;
		
		juniper)
			grep -Eq \
			"^set system|^set interfaces|^set routing-options|^set security" \
			"$file"
			;;
	
        *)
            [[ -s "$file" ]]
            ;;
    esac
}

# ==================================================
# BACKUP FUNCTION
# ==================================================
run_backup() {

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[FATAL] devices.conf not found: $CONFIG_FILE"
        exit 1
    fi

    # Verify `expect` is available in THIS environment (web/cron PATH may differ
    # from your interactive shell). Without it, every device backup fails.
    if [[ -z "$EXPECT_BIN" ]]; then
        echo "[FATAL] 'expect' command not found in PATH ($PATH)."
        echo "[HINT]  The web server runs with a minimal PATH. Install expect"
        echo "[HINT]  (e.g. 'apk add expect' or 'apt-get install -y expect') and"
        echo "[HINT]  make sure it is on the PATH of the user running the web app."
        echo "[DONE] Backup completed"
        echo "[LOG] $RUN_LOG"
        return 1
    fi

    while IFS=',' read -r vendor ip username password enable_secret ssh_port_field || [[ -n "$vendor" ]]; do

        # Trim spaces + Windows CR (nano on Windows leaves \r -> login fails)
        vendor="${vendor%$'\r'}"; vendor="$(echo "$vendor" | xargs 2>/dev/null || echo "$vendor")"
        ip="${ip%$'\r'}"; ip="$(echo "$ip" | xargs 2>/dev/null || echo "$ip")"
        username="${username%$'\r'}"; username="$(echo "$username" | xargs 2>/dev/null || echo "$username")"
        password="${password%$'\r'}"
        enable_secret="${enable_secret%$'\r'}"
        ssh_port_field="${ssh_port_field%$'\r'}"; ssh_port_field="$(echo "$ssh_port_field" | xargs 2>/dev/null || echo "$ssh_port_field")"

        [[ -z "$vendor" || "$vendor" == \#* ]] && continue

        # SSH port: 6th CSV field wins, else host:port suffix, else default/env.
        # NOTE: vendor folder + filenames use the plain host (no :port).
        SSH_PORT="$DEFAULT_SSH_PORT"
        [[ -n "$ssh_port_field" ]] && SSH_PORT="$ssh_port_field"
        DEV_HOST="$ip"
        if [[ "$ip" == *:* ]]; then
            DEV_HOST="${ip%%:*}"
            _p="${ip##*:}"
            [[ -z "$ssh_port_field" && "$_p" =~ ^[0-9]+$ ]] && SSH_PORT="$_p"
        fi
        # Filenames must not contain ':' — use host only.
        SAFE_IP="$DEV_HOST"

        echo "[INFO] Processing $vendor $DEV_HOST (ssh port $SSH_PORT, direct/LAN — no WireGuard required)"

        # Vendor folder
        TARGET_DIR="$BACKUP_DIR/$vendor"
        mkdir -p "$TARGET_DIR"

        # Device timestamp
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

        # Backup file (config output via expect log_file)
        BACKUP_FILE="${SAFE_IP}_${TIMESTAMP}.log"
        BACKUP_PATH="$TARGET_DIR/$BACKUP_FILE"

        # Per-device transcript (expect stdout/stderr — TEMPORARY working file
        # for the mikrotik rebuild; deleted after each device so one run
        # leaves exactly one file per device)
        LOG_FILE="$TARGET_DIR/${SAFE_IP}_${TIMESTAMP}.debug.log"

        case "$vendor" in

            cisco)
                expect "$TEMPLATE_DIR/cisco.exp" \
                    "$DEV_HOST" "$username" "$password" "$enable_secret" \
                    "$BACKUP_PATH" >> "$LOG_FILE" 2>&1             
				if [[ -f "$BACKUP_PATH" ]]; then
				sed -i '/^spawn ssh /d' "$BACKUP_PATH"
				sed -i '/Password:/d' "$BACKUP_PATH"
				sed -i '/^[A-Za-z0-9._-]\+>enable$/d' "$BACKUP_PATH"
				sed -i '/^[A-Za-z0-9._-]\+#terminal length 0$/d' "$BACKUP_PATH"
				sed -i '/^[A-Za-z0-9._-]\+#show running-config$/d' "$BACKUP_PATH"
				sed -i '/^[A-Za-z0-9._-]\+#$/d' "$BACKUP_PATH"

				fi
				;;
            ciscoasa)
                expect "$TEMPLATE_DIR/ciscoasa.exp" \
                    "$DEV_HOST" "$username" "$password" "$enable_secret" \
                    "$BACKUP_PATH" >> "$LOG_FILE" 2>&1
				if [[ -f "$BACKUP_PATH" ]]; then
				sed -i '/^spawn ssh /d' "$BACKUP_PATH"
				sed -i "/Permanently added .*known hosts/d" "$BACKUP_PATH"
				sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
				sed -i '/^ciscoasa> enable$/d' "$BACKUP_PATH"
				sed -i '/^ciscoasa# ter pager 0$/d' "$BACKUP_PATH"
				sed -i '/^ciscoasa# show running-config$/d' "$BACKUP_PATH"
				sed -i '/^ciscoasa>$/d' "$BACKUP_PATH"
				sed -i '/^ciscoasa#$/d' "$BACKUP_PATH"
				sed -i '/./,$!d' "$BACKUP_PATH"
				fi
				;;
            h3c)
                expect "$TEMPLATE_DIR/h3c.exp" \
					"$DEV_HOST" "$username" "$password" \
					"$BACKUP_PATH" >> "$LOG_FILE" 2>&1
				if [[ -f "$BACKUP_PATH" ]]; then
				sed -i '/^spawn ssh /d' "$BACKUP_PATH"
				sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
				sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
				sed -i '/./,$!d' "$BACKUP_PATH"
				fi
				;;
				
		    h3c_1920)
                expect "$TEMPLATE_DIR/h3c_1920.exp" \
					"$DEV_HOST" "$username" "$password" \
					"$BACKUP_PATH" >> "$LOG_FILE" 2>&1
				if [[ -f "$BACKUP_PATH" ]]; then
				sed -i '/^spawn ssh /d' "$BACKUP_PATH"
				sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
				sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
				sed -i '/./,$!d' "$BACKUP_PATH"
				fi
				;;

            arista)
                expect "$TEMPLATE_DIR/arista.exp" \
                    "$DEV_HOST" "$username" "$password" "$enable_secret" \
                    "$BACKUP_PATH" >> "$LOG_FILE" 2>&1
                if [[ -f "$BACKUP_PATH" ]]; then
				sed -i '/^spawn ssh /d' "$BACKUP_PATH"
				sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
				sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
				sed -i '/[Ll][Aa][Ss][Tt] [Ll][Oo][Gg][Ii][Nn]:/d' "$BACKUP_PATH"
				fi
                ;;

            mikrotik)
				expect "$TEMPLATE_DIR/mikrotik.exp" \
					"$DEV_HOST" "$username" "$password" \
					"$BACKUP_PATH" "$SSH_PORT" "$SSH_TIMEOUT" > "$LOG_FILE" 2>&1
					if [[ -f "$BACKUP_PATH" ]]; then
					sed -i '/^spawn ssh /d' "$BACKUP_PATH"
					sed -i "/password:/Id" "$BACKUP_PATH"
					sed -i '/\/export show-sensitive terse/d' "$BACKUP_PATH"
					sed -i '/\/export terse/d' "$BACKUP_PATH"
					sed -i '/^\[.*@.*\][[:space:]]*[>#]/d' "$BACKUP_PATH"
					fi
					# Fallback: on RouterOS 7 expect's log_file sometimes misses
					# the export bytes (terminal probing/paging), while the stdout
					# transcript (LOG_FILE) holds the complete session. Rebuild the
					# backup from the transcript when validation would otherwise fail.
					if ! validate_backup "mikrotik" "$BACKUP_PATH" && [[ -s "$LOG_FILE" ]]; then
						echo "[INFO] mikrotik log_file incomplete — rebuilding backup from transcript"
						_MT_ESC="$(printf '\033')"
						sed -e "s/${_MT_ESC}\[[0-9;?]*[a-zA-Z]//g" \
							-e "s/${_MT_ESC}[()][0-9A-B]//g" \
							-e "s/${_MT_ESC}[^[]//g" \
							-e 's/\r//g' \
							-e '/^spawn ssh /d' \
							-e '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' \
							-e '/Warning: Permanently added /d' \
							-e '/\/export show-sensitive terse/d' \
							-e '/\/export terse/d' \
							-e '/^\[.*@.*\][[:space:]]*[>#]/d' \
							-e '/^Connection to .* closed\./d' \
							-e '/^interrupted$/d' \
							-e '/^Press F1 for help$/d' \
							-e '/^\/quit$/d' \
							"$LOG_FILE" > "$BACKUP_PATH.tmp" && mv "$BACKUP_PATH.tmp" "$BACKUP_PATH"
					fi
				;;
            aruba)
                expect "$TEMPLATE_DIR/arubacx.exp" \
                    "$DEV_HOST" "$username" "$password" \
                    "$BACKUP_PATH" >> "$LOG_FILE" 2>&1
					if [[ -f "$BACKUP_PATH" ]]; then
					sed -i '/^spawn ssh /d' "$BACKUP_PATH"
					sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
					sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
					sed -i '/./,$!d' "$BACKUP_PATH"
					fi
					;;
			fortigate)
				expect "$TEMPLATE_DIR/fortigate.exp" \
					"$DEV_HOST" "$username" "$password" \
					"$BACKUP_PATH" >> "$LOG_FILE" 2>&1

					if [[ -f "$BACKUP_PATH" ]]; then
					sed -i '/^spawn ssh /d' "$BACKUP_PATH"
					sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
					sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
					sed -i '/config system console/d' "$BACKUP_PATH"
					sed -i '/set output standard/d' "$BACKUP_PATH"
					sed -i '/^end$/d' "$BACKUP_PATH"
					sed -i '/show full-configuration/d' "$BACKUP_PATH"
					sed -i '/FortiGate-.*# config system console/d' "$BACKUP_PATH"
					sed -i '/FortiGate-.*(console) # set output standard/d' "$BACKUP_PATH"
					sed -i '/FortiGate-.*(console) # end/d' "$BACKUP_PATH"
					sed -i '/FortiGate-.*# show full-configuration/d' "$BACKUP_PATH"
					fi
					;;
			juniper)
				expect "$TEMPLATE_DIR/juniper.exp" \
					"$DEV_HOST" "$username" "$password" \
					"$BACKUP_PATH" >> "$LOG_FILE" 2>&1

					if [[ -f "$BACKUP_PATH" ]]; then
					sed -i '/^spawn ssh /d' "$BACKUP_PATH"
					sed -i '/Permanently added .*known hosts/d' "$BACKUP_PATH"
					sed -i '/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]:/d' "$BACKUP_PATH"
					sed -i '/set cli screen-length 0/d' "$BACKUP_PATH"
					sed -i '/Screen length set to 0/d' "$BACKUP_PATH"
					sed -i '/^--- JUNOS/d' "$BACKUP_PATH"
					sed -i '/^Connection to .* closed\./d' "$BACKUP_PATH"
					fi
					;;
            *)
                echo "[WARN] Unknown vendor: $vendor"
                continue
                ;;
        esac

        # Verify
        if validate_backup "$vendor" "$BACKUP_PATH"; then

			echo "[OK] Backup saved: $BACKUP_PATH"
			# Single-file mode: the per-device transcript was only needed
			# for the mikrotik rebuild above — drop it on success so each
			# run leaves exactly one file per device.
			rm -f "$LOG_FILE"

		else

			echo "[FAIL] Backup validation failed: $DEV_HOST"
			if [[ -f "$BACKUP_PATH" ]]; then
				echo "[DEBUG] file=$BACKUP_PATH size=$(wc -c < "$BACKUP_PATH" 2>/dev/null || echo 0) bytes"
				echo "[DEBUG] --- first 20 lines of $BACKUP_PATH ---"
				head -n 20 "$BACKUP_PATH" || true
				echo "[DEBUG] --- transcript: $LOG_FILE ---"
				head -n 30 "$LOG_FILE" 2>/dev/null || true
				echo "[DEBUG] --- end ---"
			else
				echo "[DEBUG] no backup file created: $BACKUP_PATH"
				echo "[DEBUG] --- transcript: $LOG_FILE ---"
				head -n 30 "$LOG_FILE" 2>/dev/null || true
			fi
			# Single-file mode: transcript excerpts are already in the run
			# log above — remove the per-device debug file.
			rm -f "$LOG_FILE"

		fi

    done < "$CONFIG_FILE"

    echo ""
    echo "[DONE] Backup completed"
    echo "[LOG] $RUN_LOG"

    # ==================================================
    # SEND ALERTS (email / telegram) — never fail the run
    # Skipped when launched from DARKVEDA LAB portal (MVNBC_NOTIFY=python/bot):
    # the portal's watcher thread sends exactly one summary instead,
    # avoiding duplicate email+telegram per run.
    # Otherwise (standalone / cron): robust notifier ported from
    # MVNBC_Dashboard original — try php CLI (multiple names/paths),
    # then python3 fallback, then warn loudly instead of skipping silent.
    # ==================================================
    if [[ "${MVNBC_NOTIFY:-}" == "python" || "${MVNBC_NOTIFY:-}" == "bot" ]]; then
        echo "[INFO] notifier handled externally (MVNBC_NOTIFY=${MVNBC_NOTIFY})"
    else
        NOTIFY_PHP="$BASE_DIR/web/app/notify_run.php"
        NOTIFY_PY="$BASE_DIR/web/app/notify_run.py"
        NOTIFY_OUT="$LOG_DIR/notify_${RUN_ID}.log"

        PHP_BIN="$(command -v php 2>/dev/null || command -v php8.3 2>/dev/null || command -v php8.2 2>/dev/null || command -v php8.1 2>/dev/null || command -v php8.0 2>/dev/null || command -v php7.4 2>/dev/null || true)"
        for _c in /usr/local/bin/php /usr/bin/php; do
            [[ -z "$PHP_BIN" && -x "$_c" ]] && PHP_BIN="$_c"
        done
        PY_BIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"

        echo "[INFO] Notifier available: php='${PHP_BIN:-none}' python='${PY_BIN:-none}'"

        if [[ -n "$PHP_BIN" && -f "$NOTIFY_PHP" ]]; then
            "$PHP_BIN" "$NOTIFY_PHP" "$RUN_LOG" > "$NOTIFY_OUT" 2>&1
            _rc=$?
            cat "$NOTIFY_OUT"
            [[ $_rc -ne 0 ]] && echo "[WARN] php notifier exited $_rc (see $NOTIFY_OUT)"
        elif [[ -n "$PY_BIN" && -f "$NOTIFY_PY" ]]; then
            echo "[INFO] php CLI unavailable here — using python3 notifier fallback"
            "$PY_BIN" "$NOTIFY_PY" "$RUN_LOG" > "$NOTIFY_OUT" 2>&1
            _rc=$?
            cat "$NOTIFY_OUT"
            [[ $_rc -ne 0 ]] && echo "[WARN] python notifier exited $_rc (see $NOTIFY_OUT)"
        else
            echo "[WARN] Neither php nor python3 notifier is available in this environment."
            echo "[WARN] Backup alerts were NOT sent."
            echo "[HINT] Install php-cli OR add web/app/notify_run.py in this container,"
            echo "[HINT] or run the backup from the portal (MVNBC_NOTIFY=bot) instead."
        fi
    fi
}

# ==================================================
# SCHEDULE FUNCTION (CRON SAFE)
# ==================================================
schedule_backup() {

    echo ""
    echo "======================================"
    echo " Schedule Backup"
    echo "======================================"
    echo ""

    echo "1) Daily 2AM (MYT)"
    echo "2) Weekly Sunday 2AM (MYT)"
    echo "3) Hourly"
    echo "4) Custom cron"
    echo ""

    read -p "Choose option: " opt

    case "$opt" in
        1) CRON="0 2 * * *" ;;
        2) CRON="0 2 * * 0" ;;
        3) CRON="0 * * * *" ;;
        4) read -p "Enter cron format (e.g */5 * * * *): " CRON ;;
        *) echo "[ERROR] Invalid option"; return ;;
    esac

    # Same line format as the portal API (TZ-pinned, /bin/bash) so the
    # portal UI + Telegram bot recognise CLI-installed schedules too.
    # Requires the cron daemon (runs under supervisord in darkveda-portal;
    # on a standalone host: `service cron start`).
    if ! command -v crontab >/dev/null 2>&1; then
        echo "[ERROR] 'crontab' not found. Install cron first (e.g. 'apt-get install -y cron')."
        return 1
    fi
    JOB="$CRON /bin/bash $BASE_DIR/MVNBC.sh --auto"

    # install cron safely (no duplicates, keep TZ pins)
    { crontab -l 2>/dev/null | grep -v "$BASE_DIR/MVNBC.sh" | grep -v -E "^[[:space:]]*(TZ|CRON_TZ)[[:space:]]*="; echo "TZ=Asia/Kuala_Lumpur"; echo "CRON_TZ=Asia/Kuala_Lumpur"; echo "$JOB"; } | crontab -

    # get PID of cron service (for reference only)
    CRON_PID=$(pgrep cron | head -n 1)

    echo "[OK] Schedule successfully added"
    echo "[INFO] CRON: $CRON"
    echo "[INFO] COMMAND: $JOB"
    echo "[INFO] CRON PID: $CRON_PID"
}

# ==================================================
# AUTO MODE
# ==================================================
if [[ "$1" == "--auto" ]]; then
    run_backup
    exit 0
fi

# ==================================================
# MENU
# ==================================================
echo "1) Run Backup Now"
echo "2) Schedule Backup"
echo "3) Exit"
echo ""

read -p "Choose option: " opt

case "$opt" in
    1) run_backup ;;
    2) schedule_backup ;;
    *) exit 0 ;;
esac
