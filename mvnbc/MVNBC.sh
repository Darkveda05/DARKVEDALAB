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

    while IFS=',' read -r vendor ip username password enable_secret; do

        [[ -z "$vendor" || "$vendor" == \#* ]] && continue

        echo "[INFO] Processing $vendor $ip"

        # Vendor folder
        TARGET_DIR="$BACKUP_DIR/$vendor"
        mkdir -p "$TARGET_DIR"

        # Device timestamp
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

        # Backup file
        BACKUP_FILE="${ip}_${TIMESTAMP}.log"
        BACKUP_PATH="$TARGET_DIR/$BACKUP_FILE"

        # Log file per device
        LOG_FILE="$TARGET_DIR/${ip}_${TIMESTAMP}.log"

        case "$vendor" in

            cisco)
                expect "$TEMPLATE_DIR/cisco.exp" \
                    "$ip" "$username" "$password" "$enable_secret" \
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
                    "$ip" "$username" "$password" "$enable_secret" \
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
					"$ip" "$username" "$password" \
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
					"$ip" "$username" "$password" \
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
                    "$ip" "$username" "$password" "$enable_secret" \
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
					"$ip" "$username" "$password" \
					"$BACKUP_PATH" >> "$LOG_FILE" 2>&1
					if [[ -f "$BACKUP_PATH" ]]; then
					sed -i '/^spawn ssh /d' "$BACKUP_PATH"
					sed -i "/password:/Id" "$BACKUP_PATH"
					sed -i '/\/export show-sensitive terse/d' "$BACKUP_PATH"
					sed -i '/^\[.*@MikroTik\].*>$/d' "$BACKUP_PATH"
					fi
				;;
            aruba)
                expect "$TEMPLATE_DIR/arubacx.exp" \
                    "$ip" "$username" "$password" \
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
					"$ip" "$username" "$password" \
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
					"$ip" "$username" "$password" \
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
            t)
                expect "$TEMPLATE_DIR/t.exp" \
                    "$ip" "$username" "$password" "$enable_secret" \
                    "$BACKUP_PATH" >> "$LOG_FILE" 2>&1
                ;;
            *)
                echo "[WARN] Unknown vendor: $vendor"
                continue
                ;;
        esac

        # Verify
        if validate_backup "$vendor" "$BACKUP_PATH"; then

			echo "[OK] Backup saved: $BACKUP_PATH"

		else

			echo "[FAIL] Backup validation failed: $ip"

		fi

    done < "$CONFIG_FILE"

    echo ""
    echo "[DONE] Backup completed"
    echo "[LOG] $RUN_LOG"

    # ==================================================
    # SEND ALERTS (email / telegram) — never fail the run
    # Skipped when launched from DARKVEDA LAB portal (MVNBC_NOTIFY=python):
    # the portal's watcher thread sends exactly one summary instead,
    # avoiding duplicate email+telegram per run.
    # ==================================================
    NOTIFY_SCRIPT="$BASE_DIR/web/app/notify_run.php"
    if [[ "${MVNBC_NOTIFY:-}" == "python" || "${MVNBC_NOTIFY:-}" == "bot" ]]; then
        echo "[INFO] notifier handled externally (MVNBC_NOTIFY=${MVNBC_NOTIFY})"
    elif command -v php >/dev/null 2>&1 && [[ -f "$NOTIFY_SCRIPT" ]]; then
        php "$NOTIFY_SCRIPT" "$RUN_LOG" || echo "[WARN] notifier returned non-zero"
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

    echo "1) Daily 2AM"
    echo "2) Weekly Sunday 2AM"
    echo "3) Custom cron"
    echo ""

    read -p "Choose option: " opt

    case "$opt" in
        1) CRON="0 2 * * *" ;;
        2) CRON="0 2 * * 0" ;;
        3) read -p "Enter cron format (e.g */5 * * * *): " CRON ;;
        *) echo "[ERROR] Invalid option"; return ;;
    esac

    JOB="$CRON $BASE_DIR/MVNBC.sh --auto"

    # install cron safely (no duplicates)
    (crontab -l 2>/dev/null | grep -v "$BASE_DIR/MVNBC.sh"; echo "$JOB") | crontab -

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
