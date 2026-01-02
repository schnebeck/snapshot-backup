#!/bin/sh

# ==============================================================================
## @file    snapshot-backup.sh
## @brief   Unified Snapshot Backup Client & Agent (POSIX sh)
## @version 16.0
##
## @note    DEVIATION FROM STRICT POSIX:
##          This script utilizes the 'local' keyword for variable scoping.
##          This deviation is intentional to prevent global variable pollution
##          and improve maintainability in this complex codebase.
##
## @details This script implements a dynamic waterfall rotation policy.
##          It provides robust backup capabilities for local storage (atomic 
##          hardlinks) and remote storage via the embedded Rsync Agent.
##
## @license GPLv3
# ==============================================================================

set -u
export LC_ALL=C

# ==============================================================================
# 1. CONSTANTS & CONFIGURATION DEFAULTS
# ==============================================================================

SCRIPT_VERSION="16.0"
EXPECTED_CONFIG_VERSION="2.0"

# --- System Paths ---
CONFIG_FILE="/etc/snapshot-backup.conf"
LOGFILE="/var/log/snapshot-backup.log"
LOGTAG="snapshot-backup"
PIDFILE="/var/run/snapshot-backup.pid"
LOCK_DIR="${PIDFILE%.pid}.lock"

STATS_FILE=".backup_stats"
TIMESTAMP_FILE=".backup_timestamp"
LAST_VERIFY_FILE="/var/lib/snapshot-backup/last_verify.timestamp"

# --- Intervals ---
INTERVALS="hourly daily weekly monthly yearly"

# --- Runtime Globals ---
START_TIME=0
BASE_INTERVAL="daily"
RUN_MODE="AUTO"
HAS_LOCK=false
AGENT_MODE=false
DEBUG_MODE=false

# --- Agent Constants ---
readonly DEFAULT_AGENT_CONFIG="/etc/snapshot-agent.conf"
AGENT_LOCK_DIR="/var/run/snapshot-agent"
AGENT_CONFIG_FILE="$DEFAULT_AGENT_CONFIG"
BASE_STORAGE_PATH="/var/backups/snapshots"

# --- Configuration Defaults (Global) ---
BACKUP_MODE="LOCAL"
CLIENT_NAME="$(hostname)"
REMOTE_USER="root"
REMOTE_HOST="backup.server.local"
REMOTE_PORT="22"
REMOTE_KEY="/root/.ssh/id_ed25519"
REMOTE_AGENT="/usr/local/sbin/snapshot-agent.sh"
REMOTE_SSH_OPTS=""
REMOTE_STORAGE_ROOT="/var/backups/snapshots"
BACKUP_ROOT="/mnt/backup"
DEFAULT_BACKUP_ROOT="/mnt/backup"

SOURCE_DIRS="/"
EXCLUDE_PATTERNS=".cache *.tmp .thumbnails swapfile node_modules .git lost+found .Trash /var/lib/docker"
EXCLUDE_MOUNTPOINTS="/proc /sys /dev /run /tmp /mnt /media /backup /snap"

# Default Retention Policies
DEFAULT_RETAIN_HOURLY=0
DEFAULT_RETAIN_DAILY=7
DEFAULT_RETAIN_WEEKLY=4
DEFAULT_RETAIN_MONTHLY=12
DEFAULT_RETAIN_YEARLY=0

RETAIN_HOURLY=$DEFAULT_RETAIN_HOURLY
RETAIN_DAILY=$DEFAULT_RETAIN_DAILY
RETAIN_WEEKLY=$DEFAULT_RETAIN_WEEKLY
RETAIN_MONTHLY=$DEFAULT_RETAIN_MONTHLY
RETAIN_YEARLY=$DEFAULT_RETAIN_YEARLY

# Smart Purge Defaults
SPACE_LOW_LIMIT_GB=0
SMART_PURGE_SLOTS=0

# Operational Defaults
LOG_PROGRESS_INTERVAL=60
RSYNC_EXTRA_OPTS=""
DEEP_VERIFY_INTERVAL_DAYS="35"
ENABLE_NOTIFICATIONS=true
NETWORK_TIMEOUT=10

# Global runtime flags
FORCE_WEEKLY=false
FORCE_MONTHLY=false
FORCE_YEARLY=false
FORCE_VERIFY=false

# Rsync capabilities (Initialized via check_rsync_capabilities)
RSYNC_PROGRESS_OPTS=""
RSYNC_ACL_OPT=""
RSYNC_XATTR_OPT=""

# ==============================================================================
# 2. UTILITY FUNCTIONS
# ==============================================================================

## @brief Standardized logging to file, console and syslog.
log() {
    local level="$1"
    shift
    local msg="$*"
    local ts; ts=$(date "+%Y-%m-%d %H:%M:%S")
    local clean_msg; clean_msg=$(echo "$msg" | sed 's/\\e\[[0-9;]*m//g')
    local log_entry="[$ts] [$level] $clean_msg"

    if [ ! -d "$(dirname "$LOGFILE")" ]; then
        mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
    fi

    if [ -w "$(dirname "$LOGFILE")" ]; then
        if [ "$level" != "DEBUG" ] || [ "${DEBUG_MODE:-false}" = "true" ]; then
             echo "$log_entry" >> "$LOGFILE"
        fi
    fi

    if [ "$RUN_MODE" != "SERVICE" ] || [ "$level" = "ERROR" ]; then
        if [ "$level" = "DEBUG" ] && [ "${DEBUG_MODE:-false}" != "true" ]; then
            return 0
        fi
        if [ -t 1 ]; then
            case "$level" in
                ERROR) printf "\033[1;31m:: %s: %s\033[0m\n" "$level" "$msg" >&2 ;;
                WARN)  printf "\033[1;33m:: %s: %s\033[0m\n" "$level" "$msg" ;;
                INFO)  printf "\033[1;32m::\033[0m %s\n" "$msg" ;;
                DEBUG) printf "\033[1;34m:: [DEBUG]\033[0m %s\n" "$msg" ;;
                *)     printf ":: %s\n" "$msg" ;;
            esac
        else
            echo ":: [$level] $clean_msg"
        fi
    fi

    if [ "$level" != "DEBUG" ]; then
        local prio="user.info"
        case "$level" in
            ERROR) prio="user.err" ;;
            WARN)  prio="user.warning" ;;
        esac
        local safe_msg; safe_msg=$(echo "$clean_msg" | cut -c 1-1000)
        logger -t "$LOGTAG" -p "$prio" -- "$safe_msg"
    fi
}

## @brief Safe recursive delete.
safe_rm() {
    local target="$1"
    if [ -z "$target" ] || [ "$target" = "/" ]; then
        log "ERROR" "Refusing to rm -rf '$target' (safety check)"
        return 1
    fi
    if [ -e "$target" ]; then
        log "INFO" "safe_rm deleting '$target'"
        rm -rf "$target"
    fi
}

## @brief Execution Wrapper with Fallback Timeout.
compat_run_with_timeout() {
    local duration="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$duration" "$@"
        return $?
    fi
    "$@" &
    local child_pid=$!
    ( sleep "$duration"; kill -TERM "$child_pid" 2>/dev/null ) &
    local killer_pid=$!
    wait "$child_pid" 2>/dev/null
    local exit_code=$?
    kill -9 "$killer_pid" 2>/dev/null
    return $exit_code
}

## @brief Executes a command on the remote backup host.
run_remote_cmd() {
    ssh -p "$REMOTE_PORT" $REMOTE_SSH_OPTS -i "$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST" "$@"
}

## @brief Executes a remote command with a specific timeout.
run_remote_cmd_with_timeout() {
    local duration="$1"
    shift
    compat_run_with_timeout "$duration" ssh -p "$REMOTE_PORT" $REMOTE_SSH_OPTS -i "$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST" "$@"
}

## @brief Standard error exit.
die() { log "ERROR" "$1"; exit 1; }

# --- Date Function Definitions ---
if date -d "@0" +%s >/dev/null 2>&1; then
    ts_to_date() { date -d "@$1" "$2" 2>/dev/null || echo "ERROR"; }
    _parse_legacy_date() { date -d "$1" +%s 2>/dev/null || echo "0"; }
elif date -r 0 +%s >/dev/null 2>&1; then
    ts_to_date() { date -r "$1" "$2" 2>/dev/null || echo "ERROR"; }
    _parse_legacy_date() { date -j -f "%Y-%m-%d %H:%M:%S" "$1" +%s 2>/dev/null || echo "0"; }
else
    ts_to_date() { echo "ERROR: Date utility incompatible"; }
    _parse_legacy_date() { echo "0"; }
fi

## @brief Checks if all required system commands are available.
check_dependencies() {
    local dependencies="date df awk sort find ls rm mv cp grep rsync tr mountpoint"
    for cmd in $dependencies; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Required command '$cmd' not found."
        fi
    done
    
    if [ "$(ts_to_date 0 +%s)" = "ERROR: Date utility incompatible" ]; then
        die "System 'date' utility does not support timestamp conversion (-d or -r)."
    fi
}

## @brief Internal helper to parse space-separated words in a line (handles quotes).
_iterate_words_in_line() {
    local line="$1"
    local callback="$2"
    
    local old_ifs="$IFS"
    IFS=" "
    set -f
    set -- $line
    set +f
    IFS="$old_ifs"
    
    local accumulator=""
    
    for word in "$@"; do
        if [ -n "$accumulator" ]; then
            accumulator="$accumulator $word"
            case "$word" in
                *\")
                    local content="${accumulator%\"}"
                    "$callback" "$content"
                    accumulator=""
                    ;;
            esac
        else
            case "$word" in
                \"*)
                    case "$word" in
                        *\"?*|*\")
                             if [ "${#word}" -gt 1 ]; then
                                 local content="${word#\"}"
                                 content="${content%\"}"
                                 "$callback" "$content"
                             else
                                 accumulator="${word#\"}"
                             fi
                             ;;
                        *)
                             accumulator="${word#\"}"
                             ;;
                    esac
                    ;;
                *)
                    if [ -n "$word" ]; then "$callback" "$word"; fi
                    ;;
            esac
        fi
    done
    
    if [ -n "$accumulator" ]; then
        die "Syntax Error: Unclosed double quote detected in configuration line: '$line'"
    fi
}

## @brief Iterates over a newline-separated list of items.
iterate_list() {
    local list="$1"
    local callback="$2"
    
    local newline='
'
    local old_ifs="$IFS"
    IFS="$newline"
    set -f
    set -- $list
    set +f
    IFS="$old_ifs"
    
    for line in "$@"; do
        if [ -n "$line" ]; then
            _iterate_words_in_line "$line" "$callback"
        fi
    done
}

## @brief Checks rsync version for feature support (ACL, XATTR, progress2).
check_rsync_capabilities() {
    RSYNC_PROGRESS_OPTS="--progress"
    RSYNC_ACL_OPT=""
    RSYNC_XATTR_OPT=""
    
    if rsync --info=progress2 --dry-run --version >/dev/null 2>&1; then
        RSYNC_PROGRESS_OPTS="--info=progress2"
    fi
    if rsync -A --dry-run --version >/dev/null 2>&1; then
        RSYNC_ACL_OPT="-A"
    fi
    if rsync -X --dry-run --version >/dev/null 2>&1; then
        RSYNC_XATTR_OPT="-X"
    fi
}

## @brief Checks if a snapshot for the current interval already exists.
is_interval_current() {
    local path="$1"
    local int="$2"
    local ts_file="$path/$int.0/$TIMESTAMP_FILE"

    if [ ! -f "$ts_file" ]; then return 1; fi
    
    local last_ts; last_ts=$(read_timestamp "$ts_file")
    local now; now=$(date +%s)
    
    case "$int" in
        hourly)
            if [ "$(ts_to_date "$last_ts" +%Y%m%d%H)" = "$(ts_to_date "$now" +%Y%m%d%H)" ]; then return 0; fi ;;
        daily)
            if [ "$(ts_to_date "$last_ts" +%Y%m%d)" = "$(ts_to_date "$now" +%Y%m%d)" ]; then return 0; fi ;;
        weekly)
             if [ "$(ts_to_date "$last_ts" +%G%V)" = "$(ts_to_date "$now" +%G%V)" ]; then return 0; fi ;;
        monthly)
             if [ "$(ts_to_date "$last_ts" +%Y%m)" = "$(ts_to_date "$now" +%Y%m)" ]; then return 0; fi ;;
        yearly)
             if [ "$(ts_to_date "$last_ts" +%Y)" = "$(ts_to_date "$now" +%Y)" ]; then return 0; fi ;;
        *)
            if [ "$(ts_to_date "$last_ts" +%Y%m%d)" = "$(ts_to_date "$now" +%Y%m%d)" ]; then return 0; fi ;;
    esac
    return 1
}

## @brief Desktop notification wrapper.
notify() {
    local title="$1"
    local msg="$2"
    local urgency="${3:-normal}"

    if [ "$ENABLE_NOTIFICATIONS" != true ]; then return 0; fi

    (
        set +e
        if ! command -v notify-send >/dev/null 2>&1; then exit 0; fi
        local user_id; user_id=$(id -u)
        if [ "$user_id" -eq 0 ]; then
             local target_user="${SUDO_USER:-}"
             if [ -z "$target_user" ]; then
                 target_user=$(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | head -n1)
             fi
             if [ -n "$target_user" ] && id "$target_user" >/dev/null 2>&1; then
                 local target_uid; target_uid=$(id -u "$target_user")
                 export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$target_uid/bus"
                 compat_run_with_timeout 5 sudo -E -u "$target_user" notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
             fi
        else
             compat_run_with_timeout 5 notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
        fi
    ) || true
}

## @brief Ensures a variable is a positive integer.
sanitize_int() {
    local val=${1:-0}
    val=$(echo "$val" | tr -cd '0-9')
    if [ -z "$val" ]; then echo "0"; else echo "$val"; fi
}

## @brief Generic cleanup on exit.
cleanup() {
    if [ "$AGENT_MODE" = true ]; then
        agent_cleanup
        return
    fi

    local jobs; jobs=$(jobs -p)
    if [ -n "$jobs" ]; then
        kill $jobs >/dev/null 2>&1 || true
        wait $jobs 2>/dev/null || true
    fi

    if [ "$HAS_LOCK" = true ]; then
        if [ -f "$PIDFILE" ] && [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ]; then
            rm -f "$PIDFILE"
        fi
        if [ -d "$LOCK_DIR" ]; then
            rmdir "$LOCK_DIR" 2>/dev/null
        fi
    fi
    
    if [ -n "${TEMP_EXCLUDE_FILE:-}" ] && [ -f "$TEMP_EXCLUDE_FILE" ]; then
        rm -f "$TEMP_EXCLUDE_FILE"
    fi
}

## @brief Validates version compatibility with remote agent.
check_agent_version() {
    log "INFO" "Checking remote agent version..."
    local agent_ver; agent_ver=$(run_remote_cmd "$REMOTE_AGENT --action version" 2>/dev/null)
    agent_ver=$(echo "$agent_ver" | tail -n 1 | tr -d '\r')
    
    if [ -z "$agent_ver" ]; then
        log "WARN" "Remote Agent connection passed, but version check failed."
        return 0
    fi
    
    if [ "$agent_ver" != "$SCRIPT_VERSION" ]; then
        log "WARN" "Version Mismatch: Client v$SCRIPT_VERSION vs Agent v$agent_ver"
    else
        log "INFO" "Remote Agent verified (v$agent_ver)."
    fi
}

trap cleanup EXIT INT TERM

## @brief Verifies SSH connectivity to remote host.
test_remote_connection() {
    ssh -q -p $REMOTE_PORT -o BatchMode=yes -o ConnectTimeout="$NETWORK_TIMEOUT" -i "$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST" "$REMOTE_AGENT --version" >/dev/null 2>&1
    return $?
}

# --- CLI Helpers ---

## @brief CLI Helper: Checks if a backup process is currently active.
check_is_running_cli() {
    if is_backup_running; then echo "true"; exit 0; else echo "false"; exit 1; fi
}

## @brief CLI Helper: Checks if the backup for the current interval is already finished.
check_is_job_done_cli() {
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        if ! mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then
             if ! test_remote_connection; then echo "false"; exit 1; fi
             local out; out=$(run_remote_cmd_with_timeout "$NETWORK_TIMEOUT" \
                 "$REMOTE_AGENT --action check-job-done --client $CLIENT_NAME \
                 $(get_retention_args)" 2>/dev/null || echo "false")
             echo "$out"
             if [ "$out" = *"true"* ]; then exit 0; else exit 1; fi
        fi
    fi
    if is_interval_current "$BACKUP_ROOT" "$BASE_INTERVAL"; then echo "true"; exit 0; else echo "false"; exit 1; fi
}

## @brief CLI Helper: Verifies write access to the backup storage.
check_has_storage_cli() {
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
         if ! test_remote_connection; then echo "false"; exit 1; fi
         run_remote_cmd_with_timeout "$NETWORK_TIMEOUT" \
             "$REMOTE_AGENT --action check-storage --client $CLIENT_NAME" 2>/dev/null
         exit 0
    else
         if ! compat_run_with_timeout 5 touch "$BACKUP_ROOT/.storage_check" 2>/dev/null; then
             echo "false"; exit 1;
         else
             rm "$BACKUP_ROOT/.storage_check"; echo "true"; exit 0;
         fi
    fi
}

## @brief Checks if destination is inside source to prevent recursion.
check_path_safety() {
    if [ "$BACKUP_MODE" = "REMOTE" ]; then return 0; fi
    iterate_list "$SOURCE_DIRS" _check_single_path_safety
}

## @brief Internal safety check for a single source path.
_check_single_path_safety() {
    local src="$1"
    local src_clean="${src%/}/"
    local dest_clean="${BACKUP_ROOT%/}/"
    
    case "$dest_clean" in
        "$src_clean"*)
            local explicitly_excluded=false
            if echo "$EXCLUDE_MOUNTPOINTS" | grep -q "$BACKUP_ROOT"; then explicitly_excluded=true; fi
            if echo "$EXCLUDE_PATTERNS" | grep -q "$BACKUP_ROOT"; then explicitly_excluded=true; fi
            
            if [ "$explicitly_excluded" = false ]; then
                die "SAFETY ERROR: Backup destination '$BACKUP_ROOT' is inside source '$src' and not excluded. This causes infinite recursion."
            fi
            ;;
    esac
}

## @brief Internal rsync executor for a single source item.
_exec_backup_item() {
    local src="$1"
    if [ ! -e "$src" ]; then return; fi
    
    if [ "$_CTX_MODE" = "REMOTE" ]; then
         if ! run_monitored_rsync rsync $_CTX_RSYNC_OPTS -e "$_CTX_SSH_CMD_OPTS" --exclude-from="$TEMP_EXCLUDE_FILE" -R "$src" "$_CTX_DEST_BASE/"; then
             _CTX_VERIFY_STATUS=1
         fi
    else
         local rel_path="${src#/}"
         mkdir -p "$_CTX_DEST_BASE/$rel_path"
         if ! run_monitored_rsync rsync $_CTX_RSYNC_OPTS --exclude-from="$TEMP_EXCLUDE_FILE" "$src/" "$_CTX_DEST_BASE/$rel_path/"; then
             _CTX_VERIFY_STATUS=1
         fi
    fi
}

## @brief High-level backup execution controller.
core_backup_execution() {
    local _CTX_MODE="$1"
    local _CTX_DEST_BASE="$2"
    local _CTX_RSYNC_OPTS="$3"
    local _CTX_RAW_REMOTE_BASE="$4"
    local _CTX_SSH_CMD_OPTS="${5:-}"
    local _CTX_VERIFY_STATUS=0

    create_exclude_list
    iterate_list "$SOURCE_DIRS" _exec_backup_item
    
    if [ "$_CTX_MODE" = "REMOTE" ]; then
        local batch_dirs=""
        _collect_batch_mp() {
            local mp="$1"
            local rel="${mp#/}"
            if [ -n "$rel" ]; then
                batch_dirs="$batch_dirs \"$_CTX_RAW_REMOTE_BASE/$rel\""
            fi
        }
        iterate_list "$EXCLUDE_MOUNTPOINTS" _collect_batch_mp
        if [ -n "$batch_dirs" ]; then
            run_remote_cmd "mkdir -p $batch_dirs" 2>/dev/null || true
        fi
    else
        _exec_local_mp() {
            local mp="$1"
            local rel="${mp#/}"
            if [ -n "$rel" ]; then mkdir -p "$_CTX_DEST_BASE/$rel" 2>/dev/null || true; fi
        }
        iterate_list "$EXCLUDE_MOUNTPOINTS" _exec_local_mp
    fi
    
    rm -f "$TEMP_EXCLUDE_FILE"
    if [ "$_CTX_VERIFY_STATUS" -ne 0 ]; then return 1; fi
    return 0
}

## @brief Rsync wrapper that logs progress and errors.
run_monitored_rsync() {
    log "INFO" "Starting monitored rsync..."
    local last_log_time=0
    local log_interval=${LOG_PROGRESS_INTERVAL:-60}
    local status_file="/tmp/snapshot_rsync_status.$$"
    
    ("$@" --timeout=300 $RSYNC_PROGRESS_OPTS 2>&1; echo $? > "$status_file") | while IFS= read -r line; do
            if echo "$line" | grep -q "[0-9]%[ ]"; then
                local now; now=$(date +%s)
                if [ $((now - last_log_time)) -ge "$log_interval" ]; then
                     if [ "${ENABLE_NOTIFICATIONS:-false}" = true ]; then
                         local pct; pct=$(echo "$line" | grep -o "[0-9]*%" | head -1)
                         notify "Snapshot Backup" "Backup Progress: ${pct:-Running...}" "low"
                     fi
                     last_log_time=$now
                fi
            else
                if echo "$line" | grep -qiE "^rsync:|rsync error:|ERROR:|failed:|fatal:|denied"; then
                    log "ERROR" "$line"
                else
                    log "DEBUG" "$line"
                fi
            fi
    done
    
    local rsync_exit=0
    if [ -f "$status_file" ]; then
        rsync_exit=$(cat "$status_file")
        rm -f "$status_file"
    else
        rsync_exit=1
    fi
    
    if [ "$rsync_exit" -ne 0 ] && [ "$rsync_exit" -ne 24 ]; then
        log "ERROR" "Rsync failed with code $rsync_exit"
        return "$rsync_exit"
    fi
    return 0
}

## @brief Helper for show_config to print lists.
print_config_list() {
    local var_name="$1"
    eval "local val=\"\${$var_name:-}\""
    echo "$var_name='"
    if [ -n "$val" ]; then
        iterate_list "$val" _print_item
    fi
    echo "'"
}
_print_item() { echo "    \"$1\""; }

## @brief Displays current effective configuration.
show_config() {
    cat << EOF
# ==============================================================================
# Configuration for snapshot-backup.sh (v$SCRIPT_VERSION)
# ==============================================================================
CONFIG_VERSION="$EXPECTED_CONFIG_VERSION"
BACKUP_MODE="$BACKUP_MODE"
CLIENT_NAME="$CLIENT_NAME"

# Remote Settings
REMOTE_USER="$REMOTE_USER"
REMOTE_HOST="$REMOTE_HOST"
REMOTE_PORT="$REMOTE_PORT"
REMOTE_KEY="$REMOTE_KEY"
REMOTE_AGENT="$REMOTE_AGENT"
REMOTE_SSH_OPTS="$REMOTE_SSH_OPTS"
REMOTE_STORAGE_ROOT="$REMOTE_STORAGE_ROOT"

# Local Settings
BACKUP_ROOT="$BACKUP_ROOT"

# Retention
RETAIN_HOURLY=$RETAIN_HOURLY
RETAIN_DAILY=$RETAIN_DAILY
RETAIN_WEEKLY=$RETAIN_WEEKLY
RETAIN_MONTHLY=$RETAIN_MONTHLY
RETAIN_YEARLY=$RETAIN_YEARLY

# Logic
DEEP_VERIFY_INTERVAL_DAYS="$DEEP_VERIFY_INTERVAL_DAYS"
SPACE_LOW_LIMIT_GB=$SPACE_LOW_LIMIT_GB
SMART_PURGE_SLOTS=$SMART_PURGE_SLOTS

# Paths & Filters
$(print_config_list SOURCE_DIRS)
$(print_config_list EXCLUDE_PATTERNS)
$(print_config_list EXCLUDE_MOUNTPOINTS)

# System
LOGFILE="$LOGFILE"
PIDFILE="$PIDFILE"
LOG_PROGRESS_INTERVAL=$LOG_PROGRESS_INTERVAL
RSYNC_EXTRA_OPTS="$RSYNC_EXTRA_OPTS"
ENABLE_NOTIFICATIONS=$ENABLE_NOTIFICATIONS
NETWORK_TIMEOUT=$NETWORK_TIMEOUT

# Flags
FORCE_VERIFY=$FORCE_VERIFY
EOF
    exit 0
}

## @brief Mounts the backup storage (local bind or remote sshfs).
do_mount() {
    local mountpoint="$1"
    local client_override="${2:-}"
    
    if [ -z "$mountpoint" ]; then mountpoint="$BACKUP_ROOT"; fi
    if [ ! -d "$mountpoint" ]; then mkdir -p "$mountpoint"; fi
    
    if mountpoint -q "$mountpoint"; then
        log "WARN" "$mountpoint is already a mountpoint."
        return
    fi
    
    local target_client="${client_override:-$CLIENT_NAME}"
    
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        if ! command -v sshfs >/dev/null 2>&1; then
            die "sshfs is required. Please install it."
        fi
        log "INFO" "Mounting REMOTE backups for '$target_client' to $mountpoint..."
        sshfs -p "$REMOTE_PORT" \
              -o "IdentityFile=$REMOTE_KEY" \
              -o "StrictHostKeyChecking=no" \
              "$REMOTE_USER@$REMOTE_HOST:$REMOTE_STORAGE_ROOT/$target_client" \
              "$mountpoint"
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Mounted successfully at $mountpoint"
        else
            die "Failed to mount remote path."
        fi
    else
        if [ "$mountpoint" -ef "$BACKUP_ROOT" ]; then
            log "INFO" "Mountpoint is same as Backup Root."
        else
            log "INFO" "Bind mounting $BACKUP_ROOT to $mountpoint..."
            mount --bind "$BACKUP_ROOT" "$mountpoint"
            if [ $? -eq 0 ]; then
                log "SUCCESS" "Mounted successfully."
            else
                die "Failed to bind mount."
            fi
        fi
    fi
}

## @brief Unmounts a path.
do_umount() {
    local mountpoint="$1"
    if [ -z "$mountpoint" ]; then mountpoint="$BACKUP_ROOT"; fi
    if ! mountpoint -q "$mountpoint"; then
        log "WARN" "$mountpoint is not mounted."
        return
    fi
    log "INFO" "Unmounting $mountpoint..."
    umount "$mountpoint"
}

## @brief Terminates all active backup processes.
kill_active_backups() {
    set +e
    log "WARN" "Stopping active backup processes..."
    if [ -f "$PIDFILE" ]; then
        local pid; pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill -15 "$pid"
            local c=10
            while [ $c -gt 0 ]; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1; c=$((c-1))
            done
            kill -9 "$pid" 2>/dev/null
        fi
        rm -f "$PIDFILE"
    fi
    
    if [ -d "$LOCK_DIR" ]; then
        rmdir "$LOCK_DIR" 2>/dev/null
    fi

    pkill -f "$(basename "$0")" 2>/dev/null || true
    log "INFO" "Processes terminated."
    exit 0
}

## @brief Creates the temporary exclude file for rsync.
create_exclude_list() {
    if command -v mktemp >/dev/null 2>&1; then
        TEMP_EXCLUDE_FILE=$(mktemp)
    else
        TEMP_EXCLUDE_FILE="/tmp/snapshot_exclude_$$.$(date +%s)"
        if [ -e "$TEMP_EXCLUDE_FILE" ]; then rm -f "$TEMP_EXCLUDE_FILE"; fi
        touch "$TEMP_EXCLUDE_FILE"
        chmod 600 "$TEMP_EXCLUDE_FILE"
    fi

    if [ ! -w "$TEMP_EXCLUDE_FILE" ]; then
        die "Could not create temporary exclude file: $TEMP_EXCLUDE_FILE"
    fi

    iterate_list "$EXCLUDE_PATTERNS" _append_exclude
}
_append_exclude() { echo "$1" >> "$TEMP_EXCLUDE_FILE"; }

## @brief Updates the verification timestamp on success.
handle_verification_result() {
    local status="$1"
    if [ "$FORCE_VERIFY" = true ]; then
        if [ "$status" -eq 0 ]; then
             log "INFO" "\033[1;32m[VERIFY] Integrity Check: OK\033[0m"
             mkdir -p "$(dirname "$LAST_VERIFY_FILE")"
             date +%s > "$LAST_VERIFY_FILE"
        else
             log "ERROR" "\033[1;31m[VERIFY] Integrity Check: FAILED\033[0m"
             exit 1
        fi
    fi
}

## @brief Commits the temporary backup to its final destination.
finalize_transaction() {
    local int="$1"
    local final_path="$2"
    local tmp_path="$3"
    local marker_root="${4:-}" 

    local do_rotate=true
    if ! is_rotation_needed "$int" "$final_path"; then do_rotate=false; fi
    
    if [ "$do_rotate" = true ]; then
        log "INFO" "Rotation needed ($int). Shifting snapshots..."
        rotate_level "$int" "$(get_retention "$int")"
    else
        log "INFO" "In-Place Update ($int): No rotation."
        if [ -d "$final_path" ]; then safe_rm "$final_path"; fi
    fi
    
    mv "$tmp_path" "$final_path"
    chmod 700 "$final_path"
    date +%s > "$final_path/$TIMESTAMP_FILE"
    
    if [ -n "$marker_root" ]; then
        if [ "$do_rotate" = true ]; then 
            touch "$marker_root/.rotation_occurred"
        else 
            rm -f "$marker_root/.rotation_occurred"
        fi
    fi
    
    log "INFO" "Snapshot commit for $int finished."
}

## @brief Renders the snapshot list.
print_snapshot_table() {
    local root_path="$1"
    printf "%-12s %-22s %-15s\n" "Snapshot" "Timestamp" "Age"
    for i in $INTERVALS; do
        local found_snapshots; found_snapshots=$(find "$root_path" -maxdepth 1 -type d -name "$i.*" 2>/dev/null | sort -t. -k2,2n)
        
        if [ -n "$found_snapshots" ]; then
            for snap_path in $found_snapshots; do
                local snap_name; snap_name=$(basename "$snap_path")
                local ts_file="$snap_path/$TIMESTAMP_FILE"
                if [ -f "$ts_file" ]; then
                    local ts; ts=$(read_timestamp "$ts_file")
                    printf "%-12s %-22s %-15s\n" "$snap_name" "$(ts_to_date "$ts" "+%Y-%m-%d %H:%M:%S")" "$(calc_time_ago "$ts")"
                fi
            done
        fi
    done
}

# ==============================================================================
# 2.5 STATUS & METRICS
# ==============================================================================

## @brief Calculates human readable time difference.
calc_time_ago() {
    local diff=$(( $(date +%s) - $1 ))
    if [ $diff -lt 60 ]; then echo "${diff}s ago";
    elif [ $diff -lt 3600 ]; then echo "$((diff/60))m ago";
    elif [ $diff -lt 86400 ]; then echo "$((diff/3600))h ago";
    else echo "$((diff/86400)) days ago"; fi
}

## @brief Checks if a backup process with the recorded PID is running.
is_backup_running() {
    if [ -f "$PIDFILE" ]; then
        local pid; pid=$(cat "$PIDFILE")
        if [ "$pid" = "$$" ]; then return 1; fi
        if kill -0 "$pid" 2>/dev/null; then return 0; fi
    fi
    return 1
}

## @brief Extracts rsync statistics and saves them to a CSV file.
collect_stats() {
    local logfile="$1"
    local stats_history="/var/log/snapshot-backup-stats.csv"
    if [ ! -f "$logfile" ]; then return; fi
    local size_line; size_line=$(grep "Total transferred file size" "$logfile" | tail -n 1)
    if [ -n "$size_line" ]; then
        local raw_bytes; raw_bytes=$(echo "$size_line" | awk -F': ' '{print $2}' | sed 's/[^0-9]//g')
        local timestamp; timestamp=$(date +%s)
        if [ -n "$raw_bytes" ]; then
            echo "$timestamp,$raw_bytes" >> "$stats_history"
        fi
    fi
}

## @brief Prints a detailed status dashboard.
show_status() {
    echo "================================================================================"
    echo "                  SNAPSHOT BACKUP STATUS (v$SCRIPT_VERSION)"
    echo "================================================================================"
    
    local state_text="IDLE"
    local state_color="\033[1;30m"
    if is_backup_running; then
        state_text="RUNNING"
        state_color="\033[1;32m"
    elif [ -d "$LOCK_DIR" ]; then
        state_text="STALE LOCK"
        state_color="\033[1;33m"
    fi
    printf "PROCESS:      ${state_color}● ${state_text}\033[0m\n"
    
    local storage_desc="UNKNOWN"
    local free_space="-"
    
    if [ "$BACKUP_MODE" = "LOCAL" ]; then
        if [ -d "$BACKUP_ROOT" ]; then
             storage_desc="LOCAL ($BACKUP_ROOT)"
             free_space=$(df -h "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
        else
             storage_desc="NOT FOUND"
        fi
        printf "STORAGE:      ● %s\n" "$storage_desc"
        printf "FREE SPACE:   %s\n" "$free_space"
    else
        printf "STORAGE:      ● REMOTE (%s@%s)\n" "$REMOTE_USER" "$REMOTE_HOST"
        if mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then
             local fs; fs=$(df -h "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
             printf "MOUNT STATUS: MOUNTED (%s) - Free: %s\n" "$BACKUP_ROOT" "$fs"
        else
             printf "MOUNT STATUS: NOT MOUNTED\n"
        fi
    fi

    local stats_history="/var/log/snapshot-backup-stats.csv"
    if [ -f "$stats_history" ]; then
        local avg_bytes; avg_bytes=$(tail -n 10 "$stats_history" | awk -F',' '{sum+=$2; count++} END {if (count>0) print sum/count}')
        if [ -n "$avg_bytes" ] && [ "$(echo "$avg_bytes > 0" | awk '{print ($1 > 0)}')" -eq 1 ]; then
             local avg_mb; avg_mb=$(echo "$avg_bytes" | awk '{printf "%.2f", $1/1024/1024}')
             printf "AVG NEW DATA: ~%s MB (Last 10 runs)\n" "$avg_mb"
        fi
    fi
    
    echo ""
    echo "LATEST SNAPSHOTS:"
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        if mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then
             print_snapshot_table "$BACKUP_ROOT"
        else
             if ! test_remote_connection; then
                 echo "REMOTE STATUS: UNREACHABLE (Timeout)"
             else
                 echo "Fetching remote status from $REMOTE_HOST..."
                 echo "--------------------------------------------------"
                 run_remote_cmd "$REMOTE_AGENT --action status --client $CLIENT_NAME" || echo "Failed."
             fi
        fi
    else
        print_snapshot_table "$BACKUP_ROOT"
    fi
    echo ""
}

## @brief Simple success log.
log_summary() {
    log "INFO" "Backup Summary: Success."
}

# ==============================================================================
# 3. CORE LOGIC
# ==============================================================================

## @brief Unified Configuration Loader.
load_config() {
    local config_file="$1"
    
    SOURCE_DIRS="/"
    EXCLUDE_PATTERNS=""
    EXCLUDE_MOUNTPOINTS=""
    
    if [ -f "$config_file" ]; then
        local file_ver; file_ver=$(grep "^CONFIG_VERSION=" "$config_file" | head -n 1 | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        
        if [ -z "$file_ver" ]; then
             log "ERROR" "Invalid Config: CONFIG_VERSION missing in $config_file."
             exit 1
        fi

        if [ "$file_ver" != "$EXPECTED_CONFIG_VERSION" ]; then
             log "ERROR" "Config Version Mismatch in $config_file (Expected $EXPECTED_CONFIG_VERSION)."
             exit 1
        fi

        if ! sh -n "$config_file" >/dev/null 2>&1; then
             log "ERROR" "Config file syntax check failed ($config_file)."
             exit 1
        fi
        
        local default_pidfile="$PIDFILE"
        . "$config_file"
        
        if [ "$PIDFILE" != "$default_pidfile" ]; then
             local old_default_lock="${default_pidfile%.pid}.lock"
             if [ "$LOCK_DIR" = "$old_default_lock" ]; then
                 LOCK_DIR="${PIDFILE%.pid}.lock"
             fi
        fi
    fi

    RETAIN_HOURLY=$(sanitize_int "${RETAIN_HOURLY:-$DEFAULT_RETAIN_HOURLY}")
    RETAIN_DAILY=$(sanitize_int "${RETAIN_DAILY:-$DEFAULT_RETAIN_DAILY}")
    RETAIN_WEEKLY=$(sanitize_int "${RETAIN_WEEKLY:-$DEFAULT_RETAIN_WEEKLY}")
    RETAIN_MONTHLY=$(sanitize_int "${RETAIN_MONTHLY:-$DEFAULT_RETAIN_MONTHLY}")
    RETAIN_YEARLY=$(sanitize_int "${RETAIN_YEARLY:-$DEFAULT_RETAIN_YEARLY}")
    
    SPACE_LOW_LIMIT_GB=$(sanitize_int "${SPACE_LOW_LIMIT_GB:-${SMART_PURGE_LIMIT:-0}}")
    SMART_PURGE_SLOTS=$(sanitize_int "${SMART_PURGE_SLOTS:-0}")
    NETWORK_TIMEOUT=$(sanitize_int "${NETWORK_TIMEOUT:-10}")
    
    BACKUP_ROOT="${BACKUP_ROOT:-$DEFAULT_BACKUP_ROOT}"
    BACKUP_MODE="${BACKUP_MODE:-LOCAL}"
    CLIENT_NAME="${CLIENT_NAME:-$(hostname)}"
    REMOTE_PORT="${REMOTE_PORT:-22}"

    # Agent specific path mapping from config
    BASE_STORAGE_PATH="${BASE_STORAGE:-$BASE_STORAGE_PATH}"
    AGENT_LOCK_DIR="${LOCK_DIR:-$AGENT_LOCK_DIR}"

    # Set Global Base Interval once
    BASE_INTERVAL=$(detect_base_interval)
}

## @brief Removes residues from a previous crash.
cleanup_stale() {
    log "WARN" "Cleaning up residues from crashed process..."
    if [ -n "${TEMP_EXCLUDE_FILE:-}" ] && [ -f "$TEMP_EXCLUDE_FILE" ]; then
        rm -f "$TEMP_EXCLUDE_FILE"
    fi
}

## @brief Atomically acquires a lock.
acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$PIDFILE"
        HAS_LOCK=true
        return 0
    fi

    local pid=""
    if [ -f "$PIDFILE" ]; then pid=$(cat "$PIDFILE" 2>/dev/null); fi

    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log "ERROR" "Instance already running (PID: $pid). Fail Fast."
        notify "Snapshot Backup" "Backup locked by PID $pid." "critical"
        exit 2
    fi

    log "WARN" "Found stale lock (PID: $pid). Cleaning up..."
    rmdir "$LOCK_DIR" 2>/dev/null
    cleanup_stale
    
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$PIDFILE"
        HAS_LOCK=true
        return 0
    else
        log "ERROR" "Could not acquire lock (Race condition or permissions)."
        exit 2
    fi
}

## @brief Reads a timestamp file (supports Unix epoch and legacy strings).
read_timestamp() {
    local f="$1"
    if [ ! -f "$f" ]; then echo "0"; return; fi
    local content; content=$(head -n 1 "$f")
    if echo "$content" | grep -qE "^[0-9]+$"; then 
        echo "$content"
    else 
        _parse_legacy_date "$content"
    fi
}

## @brief Checks if a snapshot should be rotated (prevents double-runs in same interval).
is_rotation_needed() {
    local int=$1
    local path=$2
    
    if [ ! -f "$path/$TIMESTAMP_FILE" ]; then return 0; fi
    local ts; ts=$(read_timestamp "$path/$TIMESTAMP_FILE")
    
    if [ "$int" = "hourly" ] && [ "$RETAIN_HOURLY" -gt 0 ]; then
        if [ "$(ts_to_date "$ts" +%Y%m%d%H)" != "$(ts_to_date "$START_TIME" +%Y%m%d%H)" ]; then return 0; fi
    else
        if [ "$(ts_to_date "$ts" +%Y%m%d)" != "$(ts_to_date "$START_TIME" +%Y%m%d)" ]; then return 0; fi
    fi
    return 1
}

## @brief Checks if a specific interval is due for promotion.
is_promotion_due() {
    local tgt=$1
    local src_ts=$2
    
    if [ ! -f "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE" ]; then echo "true"; return; fi
    
    local last_ts; last_ts=$(read_timestamp "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE")
    local age=$((src_ts - last_ts))
    local due=false
    
    case "$tgt" in
        hourly)  if [ "$age" -ge 3000 ]; then due=true; fi ;;
        daily)   if [ "$(ts_to_date "$src_ts" +%Y%m%d)" != "$(ts_to_date "$last_ts" +%Y%m%d)" ]; then due=true; fi ;;
        weekly)  if [ "$(ts_to_date "$src_ts" +%G%V)" != "$(ts_to_date "$last_ts" +%G%V)" ]; then due=true; fi ;;
        monthly) if [ "$(ts_to_date "$src_ts" +%Y%m)" != "$(ts_to_date "$last_ts" +%Y%m)" ]; then due=true; fi ;;
        yearly)  if [ "$(ts_to_date "$src_ts" +%Y)" != "$(ts_to_date "$last_ts" +%Y)" ]; then due=true; fi ;;
    esac
    echo "$due"
}

## @brief Evaluates the retention count for an interval.
get_retention() {
    local upper_int; upper_int=$(echo "$1" | tr '[:lower:]' '[:upper:]')
    local var="RETAIN_${upper_int}"
    eval "echo \"\${$var}\""
}

## @brief Finds the first interval with RETAIN > 0.
detect_base_interval() {
    for i in $INTERVALS; do
        if [ "$(get_retention "$i")" -gt 0 ]; then
            echo "$i"
            return
        fi
    done
    echo "daily"
}

## @brief Returns the previous level in the waterfall.
get_source_interval_for() {
    case "$1" in
        daily)   echo "hourly" ;;
        weekly)  echo "daily" ;;
        monthly) echo "weekly" ;;
        yearly)  echo "monthly" ;;
        *)       echo "none" ;;
    esac
}

## @brief Gets the highest existing index for an interval.
get_oldest_index() {
    local int=$1
    find "$BACKUP_ROOT" -maxdepth 1 -name "${int}.*" -type d | sed "s/^.*${int}\.//" | grep -E "^[0-9]+$" | sort -rn | head -n 1 || echo "-1"
}

## @brief Renames snapshots to fill gaps in numbering.
consolidate_snapshots() {
    local int="$1"
    local target_index=0
    find "$BACKUP_ROOT" -maxdepth 1 -name "$int.*" -type d | sed "s/^.*${int}\.//" | grep -E "^[0-9]+$" | sort -n | while read current_index; do
        if [ "$current_index" -ne "$target_index" ]; then
            log "WARN" "Consolidating gap: $int.$current_index -> $int.$target_index"
            mv "$BACKUP_ROOT/$int.$current_index" "$BACKUP_ROOT/$int.$target_index"
        fi
        target_index=$((target_index+1))
    done
}

## @brief Removes snapshots exceeding the retention limit.
prune_snapshots() {
    local int="$1"
    local limit="$2"
    if [ "$limit" -lt 0 ]; then return; fi
    
    find "$BACKUP_ROOT" -maxdepth 1 -name "$int.*" -type d | while read directory_path; do
        local idx="${directory_path##*.}"
        case "$idx" in ''|*[!0-9]*) continue ;; esac
        if [ "$idx" -ge "$limit" ]; then
             log "WARN" "Retention Prune: Deleting $int.$idx (Limit: $limit)"
             safe_rm "$directory_path"
        fi
    done
}

## @brief Executes the cascading promotion logic.
run_waterfall_logic() {
    local promotion_occurred=true
    local loop_count=0
    local promoted_levels=""

    while [ "$promotion_occurred" = true ]; do
        promotion_occurred=false
        loop_count=$((loop_count+1))
        if [ "$loop_count" -gt 10 ]; then log "WARN" "Cascade limit reached."; break; fi
        
        for level in $INTERVALS; do
             if echo "$promoted_levels" | grep -q "|$level|"; then continue; fi
             
             local upper_level; upper_level=$(echo "$level" | tr '[:lower:]' '[:upper:]')
             local force_var="FORCE_${upper_level}"
             local force_val; eval "force_val=\${$force_var:-false}"
             
             if check_promote "$level" "$force_val"; then
                  promotion_occurred=true
                  promoted_levels="$promoted_levels|$level|"
                  local src_int; src_int=$(get_source_interval_for "$level")
                  if [ "$src_int" != "none" ]; then consolidate_snapshots "$src_int"; fi
             fi
        done
    done
}

## @brief Shifts snapshots by incrementing their index.
rotate_level() {
    local int=$1
    local limit=$2
    if [ "$limit" -le 0 ]; then return; fi
    
    consolidate_snapshots "$int"
    
    local i=$limit
    while [ "$i" -ge 0 ]; do
        if [ -d "$BACKUP_ROOT/$int.$i" ]; then
            if [ "$i" -ge "$((limit-1))" ]; then
                log "WARN" "Retention Prune: Deleting $int.$i (Limit: $limit)"
                safe_rm "$BACKUP_ROOT/$int.$i"
            else
                mv "$BACKUP_ROOT/$int.$i" "$BACKUP_ROOT/$int.$((i+1))"
            fi
        fi
        i=$((i-1))
    done
}

## @brief Finds the best candidate snapshot to be promoted to a higher level.
find_promotion_candidate() {
    local src="$1"
    local tgt="$2"
    local indices; indices=$(find "$BACKUP_ROOT" -maxdepth 1 -name "${src}.*" -type d | sed "s/^.*${src}\.//" | grep -E "^[0-9]+$" | sort -rn)
    
    for idx in $indices; do
        local path="$BACKUP_ROOT/$src.$idx"
        local ts; ts=$(read_timestamp "$path/$TIMESTAMP_FILE")
        if [ "$ts" -eq 0 ]; then continue; fi
        
        local tgt_ts=0
        if [ -f "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE" ]; then
             tgt_ts=$(read_timestamp "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE")
        fi
        
        if [ "$ts" -eq "$tgt_ts" ]; then continue; fi
        if [ "$(is_promotion_due "$tgt" "$ts")" = "true" ]; then echo "$idx"; return 0; fi
    done
    echo "-1"
}

## @brief Orchestrates the promotion of a lower interval snapshot to a higher interval.
check_promote() {
    local tgt=$1
    local force=$2
    local src; src=$(get_source_interval_for "$tgt")
    local start_ts=0
    if [ "$src" = "none" ]; then return; fi
    
    local tgt_retain; tgt_retain=$(get_retention "$tgt")
    if [ "$tgt_retain" -le 0 ] && [ "$force" != true ]; then return; fi
    
    local s_idx="-1"
    local promote=false
    
    if [ "$force" = true ]; then
        s_idx=$(get_oldest_index "$src")
        start_ts=$(read_timestamp "$BACKUP_ROOT/$src.$s_idx/$TIMESTAMP_FILE")
        promote=true
    else
        s_idx=$(find_promotion_candidate "$src" "$tgt")
        if [ "$s_idx" != "-1" ]; then promote=true; fi
    fi
    
    if [ "$s_idx" = "-1" ]; then return; fi
     
    local src_path="$BACKUP_ROOT/$src.$s_idx"
    local src_ts; src_ts=$(read_timestamp "$src_path/$TIMESTAMP_FILE")
    
    if [ -f "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE" ]; then
        local tgt_ts; tgt_ts=$(read_timestamp "$BACKUP_ROOT/$tgt.0/$TIMESTAMP_FILE")
        if [ "$src_ts" -le "$tgt_ts" ] && [ "$src_ts" -gt 0 ]; then return; fi
    fi
    
    if [ "$promote" = true ]; then
        local t_tmp="$BACKUP_ROOT/$tgt.0.tmp"
        rm -rf "$t_tmp"
        local src_retain; src_retain=$(get_retention "$src")
        local method="COPY"
        local count; count=$(find "$BACKUP_ROOT" -maxdepth 1 -name "$src.*" -type d | wc -l)
        local oldest; oldest=$(find "$BACKUP_ROOT" -maxdepth 1 -name "$src.*" -type d | sed "s/^.*$src\.//" | grep -E "^[0-9]+$" | sort -rn | head -n 1)

        if [ "$force" = "true" ]; then method="COPY";
        elif [ "$count" -gt "$src_retain" ] && [ "$s_idx" -eq "$oldest" ]; then method="MOVE";
        else method="COPY"; fi
        
        log "INFO" "Promoting $src.$s_idx -> $tgt.0 via [$method]."
        
        if [ "$method" = "MOVE" ]; then 
            mv "$src_path" "$t_tmp" || { log "ERROR" "Promotion MOVE failed"; return 1; }
        else 
            cp -al "$src_path" "$t_tmp" || { log "ERROR" "Promotion COPY failed"; return 1; }
        fi
        
        if [ -f "$t_tmp/.backup_timestamp" ]; then rm "$t_tmp/.backup_timestamp"; fi
        if [ -f "$src_path/.backup_timestamp" ]; then cp "$src_path/.backup_timestamp" "$t_tmp/"; fi
        
        rotate_level "$tgt" $(get_retention "$tgt")
        mv "$t_tmp" "$BACKUP_ROOT/$tgt.0" || { log "ERROR" "Final promotion move failed"; return 1; }
        log "SUCCESS" "Promoted to $tgt.0"
        return 0
    fi
    return 1
}

## @brief Reduces retention levels temporarily if storage space is critically low.
apply_smart_retention_policy() {
    if [ "$SPACE_LOW_LIMIT_GB" -le 0 ]; then return; fi
    
    local avail_gb; avail_gb=$(($(df -P "$BACKUP_ROOT" | awk 'NR==2 {print $4}') / 1024 / 1024))
    
    if [ "$avail_gb" -lt "$SPACE_LOW_LIMIT_GB" ]; then
        log "WARN" "Smart purge triggered: Available ${avail_gb}GB < Limit ${SPACE_LOW_LIMIT_GB}GB."
        
        if [ "$SMART_PURGE_SLOTS" -gt 0 ]; then
             RETAIN_DAILY=$((RETAIN_DAILY - SMART_PURGE_SLOTS))
             if [ "$RETAIN_DAILY" -lt 1 ]; then RETAIN_DAILY=1; fi
             
             RETAIN_WEEKLY=$((RETAIN_WEEKLY - SMART_PURGE_SLOTS))
             if [ "$RETAIN_WEEKLY" -lt 1 ]; then RETAIN_WEEKLY=1; fi
             
             log "WARN" "Policies adjusted: Daily=${RETAIN_DAILY}, Weekly=${RETAIN_WEEKLY}"
        fi
        
        prune_snapshots "daily" "$RETAIN_DAILY"
        prune_snapshots "weekly" "$RETAIN_WEEKLY"
    fi
}

## @brief Centralized retention and rotation logic.
finalize_retention_flow() {
    apply_smart_retention_policy
    for int in $INTERVALS; do
        consolidate_snapshots "$int"
    done
    run_waterfall_logic
    for int in $INTERVALS; do
        prune_snapshots "$int" "$(get_retention "$int")"
    done
}

## @brief Formats retention settings as CLI arguments.
get_retention_args() {
    echo "--retain-hourly ${RETAIN_HOURLY:-0} --retain-daily ${RETAIN_DAILY:-0} --retain-weekly ${RETAIN_WEEKLY:-0} --retain-monthly ${RETAIN_MONTHLY:-0} --retain-yearly ${RETAIN_YEARLY:-0}"
}

# ==============================================================================
# 4. AGENT LOGIC (Server Side Actions)
# ==============================================================================

## @brief Agent-side lock cleanup.
agent_cleanup() {
    if [ -n "${CLIENT_NAME:-}" ] && [ -d "$AGENT_LOCK_DIR" ]; then
        local lock_file_path="$AGENT_LOCK_DIR/$CLIENT_NAME.lock"
        if [ -f "$lock_file_path" ]; then
            local lock_pid; lock_pid=$(cat "$lock_file_path" 2>/dev/null)
            if [ "$lock_pid" = "$$" ]; then 
                rm -f "$lock_file_path"
                rmdir "$AGENT_LOCK_DIR" 2>/dev/null || true
            fi
        fi
    fi
}

## @brief Validates client name against path traversal and special characters.
validate_client_name() {
    local name_to_validate="$1"
    if [ -z "$name_to_validate" ]; then die "No client name provided."; fi
    if echo "$name_to_validate" | grep -q "[^a-zA-Z0-9._-]"; then
        die "Invalid client name: '$name_to_validate'. Allowed: A-Z, 0-9, '.', '_', '-'"
    fi
    case "$name_to_validate" in *".."*|*"/"*|*"\\"*) die "Security Error: Path traversal.";; esac
}

## @brief Checks if storage for a client is writable.
do_check_storage() {
    local check_path="$BASE_STORAGE_PATH"
    if [ -n "$CLIENT_NAME" ]; then check_path="$BASE_STORAGE_PATH/$CLIENT_NAME"; fi
    
    if [ ! -d "$check_path" ]; then 
        mkdir -p "$check_path" 2>/dev/null
    fi
    
    local check_file="$check_path/.write_test_$$"
    if touch "$check_file" 2>/dev/null; then
        rm -f "$check_file"
        echo "true"
    else
        echo "false"
    fi
    exit 0
}

## @brief Prepares the temporary work directory for an incoming backup.
do_prepare() {
    if [ ! -d "$AGENT_LOCK_DIR" ]; then mkdir -p "$AGENT_LOCK_DIR"; chmod 700 "$AGENT_LOCK_DIR"; fi

    local lock_file_path="$AGENT_LOCK_DIR/$CLIENT_NAME.lock"
    local stale_reset=false
    
    if [ -f "$lock_file_path" ]; then
        local pid_in_lock; pid_in_lock=$(cat "$lock_file_path" 2>/dev/null)
        if kill -0 "$pid_in_lock" 2>/dev/null; then die "Process is already locked by PID $pid_in_lock.";
        else rm -f "$lock_file_path"; stale_reset=true; fi
    fi
    
    echo $$ > "$lock_file_path"
    HAS_LOCK=true
    
    local client_root_path="$BASE_STORAGE_PATH/$CLIENT_NAME"
    if [ ! -d "$client_root_path" ]; then mkdir -p "$client_root_path"; fi
    chmod 700 "$client_root_path" 2>/dev/null || true

    local temporary_work_dir="$client_root_path/$BASE_INTERVAL.0.tmp"
    
    if [ -d "$temporary_work_dir" ]; then
        local tmp_mtime; tmp_mtime=$(stat -c %Y "$temporary_work_dir" 2>/dev/null || echo "0")
        local now_time; now_time=$(date +%s)
        if [ $((now_time - tmp_mtime)) -gt 86400 ]; then safe_rm "$temporary_work_dir"; fi
    fi
    if [ "$stale_reset" = true ] && [ -d "$temporary_work_dir" ]; then rm -rf "$temporary_work_dir"; fi
    
    if [ ! -d "$temporary_work_dir" ]; then
        mkdir -p "$temporary_work_dir"
        chmod 700 "$temporary_work_dir"
        local current_zero_dir="$client_root_path/$BASE_INTERVAL.0"
        if [ -d "$current_zero_dir" ]; then cp -al "$current_zero_dir/." "$temporary_work_dir/" 2>/dev/null || true; fi
        chmod 700 "$temporary_work_dir"
    fi
    touch "$temporary_work_dir"; touch "$temporary_work_dir/.backup_in_progress"
}

## @brief Finalizes the transaction by moving the temporary directory to .0.
do_commit() {
    local client_root_path="$BASE_STORAGE_PATH/$CLIENT_NAME"
    local temporary_work_dir="$client_root_path/$BASE_INTERVAL.0.tmp"
    if [ ! -d "$temporary_work_dir" ]; then die "Temporary directory not found."; fi
    rm -f "$temporary_work_dir/.backup_in_progress"
    
    local current_zero_dir="$client_root_path/$BASE_INTERVAL.0"
    
    # Temporarily scope BACKUP_ROOT for finalize_transaction
    (
        BACKUP_ROOT="$client_root_path"
        finalize_transaction "$BASE_INTERVAL" "$current_zero_dir" "$temporary_work_dir" "$client_root_path"
    )
}

## @brief Triggers the retention and rotation logic on the server side.
do_purge() {
    local client_root_path="$BASE_STORAGE_PATH/$CLIENT_NAME"
    
    (
        BACKUP_ROOT="$client_root_path"
        finalize_retention_flow
        rm -f "$client_root_path/.rotation_occurred"
    )
}

## @brief Agent-side check if a client interval is current.
do_check_job_done() {
    local client_root_path="$BASE_STORAGE_PATH/$CLIENT_NAME"
    if is_interval_current "$client_root_path" "$BASE_INTERVAL"; then echo "true"; else echo "false"; fi
    exit 0
}

## @brief Agent-side status report.
do_status() {
    local client_root_path="$BASE_STORAGE_PATH/$CLIENT_NAME"
    if [ ! -d "$client_root_path" ]; then die "Client not found."; fi
    log "INFO" "Status report for $CLIENT_NAME"
    print_snapshot_table "$client_root_path"
}

## @brief Installs the script as an agent and creates a shell wrapper.
do_install() {
    local target_user="${1:-backup}"
    local wrapper_path="${WRAPPER_PATH:-/usr/local/bin/snapshot-wrapper.sh}"
    if [ "$(id -u)" -ne 0 ]; then die "Installation requires root."; fi
    local install_path="/usr/local/sbin/snapshot-agent.sh"
    if ! [ "$0" -ef "$install_path" ]; then cp -f "$0" "$install_path"; fi
    chmod 700 "$install_path"
    chown 0:0 "$install_path"
    
    local install_log="/tmp/backup-simulation/install_log"
    mkdir -p "$(dirname "$install_log")"
    if ! id "$target_user" >/dev/null 2>&1; then
        echo "useradd $target_user" >> "$install_log"
    fi
    echo "chown 0:0 $install_path" >> "$install_log"
    echo "Created wrapper: $wrapper_path" >> "$install_log"

    cat > "$wrapper_path" <<EOF
#!/bin/bash
export LC_ALL=C
CMD="\${SSH_ORIGINAL_COMMAND:-\$*}"
case "\$CMD" in
    *snapshot-agent.sh*|*snapshot-agent*|*check-job-done*|*snapshot-backup*|*--status*|*--action*|exit) exec $install_path \$CMD ;;
    *sftp-server*) exec /usr/lib/openssh/sftp-server ;;
    rsync*) exec \$CMD ;;
    *) echo "Access Denied."; exit 1 ;;
esac
EOF
    chmod +x "$wrapper_path"
    log "INFO" "Installation complete. Agent at $install_path"
}

## @brief Deploys the current script to a remote server.
do_deploy_agent() {
    local target="$1"
    if [ -z "$target" ]; then target="$REMOTE_USER@$REMOTE_HOST"; fi
    log "INFO" "Deploying Unified Agent to $target..."
    local self_path="$0"
    if [ ! -f "$self_path" ]; then self_path="./snapshot-backup.sh"; fi
    local remote_dest="/usr/local/sbin/snapshot-agent.sh"
    if ! scp -P $REMOTE_PORT -i "$REMOTE_KEY" $REMOTE_SSH_OPTS "$self_path" "$target:$remote_dest"; then
        die "SCP failed."
    fi
    run_remote_cmd "$remote_dest --agent-mode --action install"
    log "INFO" "Deployment successful."
}

## @brief Wizard for setting up a remote server (Key generation, deployment, hardening).
do_setup_remote() {
    local target="$1"
    if [ -z "$target" ]; then target="$REMOTE_USER@$REMOTE_HOST"; fi

    if [ -z "$target" ] || [ "$target" = "@" ]; then 
        die "Usage: --setup-remote user@host (or set REMOTE_USER/HOST in config)"; 
    fi
    
    log "INFO" "Starting Remote Server Setup Wizard..."
    log "INFO" "Target: $target"
    log "INFO" "Client Name: $CLIENT_NAME"

    local key_file="$REMOTE_KEY"
    eval key_file=$key_file
    
    if [ ! -f "$key_file" ]; then
        log "WARN" "SSH Key ($key_file) not found. Generating..."
        mkdir -p "$(dirname "$key_file")"
        ssh-keygen -t ed25519 -f "$key_file" -N "" || die "Key generation failed."
    fi
    
    log "INFO" "Checking connectivity to server..."
    local key_is_valid=false
    
    if ssh -q -o BatchMode=yes -o ConnectTimeout=5 -i "$key_file" "$target" "snapshot-agent.sh --version" >/dev/null 2>&1; then
        log "INFO" "SSH Key accepted (Agent Wrapper active). Skipping install."
        key_is_valid=true
    elif ssh -q -o BatchMode=yes -o ConnectTimeout=5 -i "$key_file" "$target" "exit 0" >/dev/null 2>&1; then
        log "INFO" "SSH Key accepted (Standard Shell). Skipping install."
        key_is_valid=true
    else
        local output; output=$(ssh -q -o BatchMode=yes -o ConnectTimeout=5 -i "$key_file" "$target" "echo test" 2>&1)
        if echo "$output" | grep -qE "Access Denied|Unknown Agent Action|snapshot-agent"; then
             log "INFO" "SSH Key accepted (Restricted Environment detected). Skipping install."
             key_is_valid=true
        fi
    fi

    if [ "$key_is_valid" = false ]; then
         log "INFO" "Key not accepted yet. Attempting to install (Password may be required)..."
         if command -v ssh-copy-id >/dev/null 2>&1; then
             if ! ssh-copy-id -i "$key_file.pub" "$target"; then
                 die "ssh-copy-id failed. Please check connectivity and credentials."
             fi
         else
             log "WARN" "'ssh-copy-id' not found. Trying manual method..."
             cat "$key_file.pub" | ssh "$target" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
             if [ $? -ne 0 ]; then
                 die "Manual key installation failed."
             fi
         fi
    fi
    
    do_deploy_agent "$target"
    if ssh -q -o BatchMode=yes -o ConnectTimeout=5 -i "$key_file" "$target" "exit 0" >/dev/null 2>&1; then
        log "INFO" "Checking for existing client data..."
        if ssh -i "$key_file" "$target" "[ -d \"$REMOTE_STORAGE_ROOT/$CLIENT_NAME\" ]" 2>/dev/null; then
             log "WARN" "Note: Client directory '$CLIENT_NAME' seems to already exist on target."
        fi
        log "INFO" "Hardening SSH access..."
        local pub_key_content; pub_key_content=$(cat "$key_file.pub")
        local wrapper_cmd="/usr/local/bin/snapshot-wrapper.sh $CLIENT_NAME"
        local restriction="command=\"$wrapper_cmd\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
        local key_body; key_body=$(echo "$pub_key_content" | awk '{print $2}')
        ssh -i "$key_file" "$target" "sed -i.bak '/$key_body/ s|^ssh-ed25519|$restriction ssh-ed25519|' ~/.ssh/authorized_keys"
        log "SUCCESS" "Remote setup complete. Access restricted."
    else
        log "SUCCESS" "Remote system updated. Access already restricted."
    fi
}

## @brief Runs a complete backup session.
run_backup_session() {
    local type="$1"
    notify "Snapshot Backup" "Backup started ($type)..." "normal"
    log "INFO" "--- Starting $type session ($BASE_INTERVAL) ---"
    
    check_path_safety

    if [ "$type" = "REMOTE" ]; then
        _perform_remote_backup_logic
    else
        _perform_local_backup_logic "$BASE_INTERVAL"
    fi
    
    log "INFO" "$type backup finished successfully."
    collect_stats "$LOGFILE"
    notify "Snapshot Backup" "Backup finished successfully." "normal"
}

## @brief Internal remote backup workflow.
_perform_remote_backup_logic() {
    check_agent_version
    if ! test_remote_connection; then die "Server unreachable ($REMOTE_HOST)."; fi
    
    local config_opts; config_opts="$(get_retention_args)"
    run_remote_cmd "$REMOTE_AGENT --action prepare --client $CLIENT_NAME $config_opts" || exit 1

    local target_path_raw="$REMOTE_STORAGE_ROOT/$CLIENT_NAME/$BASE_INTERVAL.0.tmp"
    local target_path_ssh="$REMOTE_USER@$REMOTE_HOST:$target_path_raw"
    
    local ssh_rsh_cmd="ssh -p $REMOTE_PORT $REMOTE_SSH_OPTS -i $REMOTE_KEY"
    local rsync_opts="-avzH $RSYNC_ACL_OPT $RSYNC_XATTR_OPT --numeric-ids --delete --partial --stats -x ${RSYNC_EXTRA_OPTS:-}"
    
    local v_status=0
    if ! core_backup_execution "REMOTE" "$target_path_ssh" "$rsync_opts" "$target_path_raw" "$ssh_rsh_cmd"; then
        v_status=1
    fi

    handle_verification_result "$v_status"
    run_remote_cmd "$REMOTE_AGENT --action commit --client $CLIENT_NAME $config_opts" || exit 1
    
    local purge_opts=""
    if [ "$SPACE_LOW_LIMIT_GB" -gt 0 ]; then purge_opts="$purge_opts --smart-purge-limit $SPACE_LOW_LIMIT_GB"; fi
    if [ "$SMART_PURGE_SLOTS" -gt 0 ]; then purge_opts="$purge_opts --smart-purge-slots $SMART_PURGE_SLOTS"; fi
    run_remote_cmd "$REMOTE_AGENT --action purge --client $CLIENT_NAME $config_opts $purge_opts" || exit 1
}

## @brief Internal local backup workflow.
_perform_local_backup_logic() {
    local int="$1"
    mkdir -p "$BACKUP_ROOT"
    local target="$BACKUP_ROOT/$int.0"
    local target_tmp="$BACKUP_ROOT/$int.0.tmp"
    
    if [ -d "$target" ]; then
        if [ -d "$target_tmp" ]; then safe_rm "$target_tmp"; fi
        cp -al "$target" "$target_tmp"
    else
        mkdir -p "$target_tmp"
    fi
    chmod 700 "$target_tmp"
    
    local rsync_opts="-aH $RSYNC_ACL_OPT $RSYNC_XATTR_OPT --delete --numeric-ids -x --stats"
    if [ -n "${RSYNC_EXTRA_OPTS:-}" ]; then rsync_opts="$rsync_opts $RSYNC_EXTRA_OPTS"; fi
    
    local v_status=0
    if ! core_backup_execution "LOCAL" "$target_tmp" "$rsync_opts" "" ""; then
        v_status=1
    fi
    
    handle_verification_result "$v_status"
    finalize_transaction "$int" "$target" "$target_tmp" ""
    finalize_retention_flow
}

# ==============================================================================
# 5. ENTRY POINT
# ==============================================================================

## @brief Sends a quick desktop status notification.
status_desktop() {
    if is_backup_running; then notify "Backup Status" "Backup Running" "normal"; return; fi
    if [ -d "$BACKUP_ROOT/$BASE_INTERVAL.0.tmp" ]; then notify "Backup Status" "Stale data detected." "critical"; return; fi
    local ts_file="$BACKUP_ROOT/$BASE_INTERVAL.0/$TIMESTAMP_FILE"
    if [ -f "$ts_file" ]; then
        local ts; ts=$(read_timestamp "$ts_file")
        notify "Backup Status" "Last Backup ($BASE_INTERVAL): $(calc_time_ago "$ts")" "normal"
    else
        notify "Backup Status" "No backups found." "normal"
    fi
}

## @brief Prints the help message.
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]
Options:
  --show-config          Print configuration.
  -c, --config FILE      Load specific config file.
  --status               Show status report.
  --desktop              Send desktop notification.
  --verify, -v           Force Deep-Checksum Verification.
  --mount [PATH]         Mount backup storage.
  --umount [PATH]        Unmount backup storage.
  --client NAME          Specify client name (Remote only).
  -f, --force-weekly     Force weekly promotion.
  -m, --force-monthly    Force monthly promotion.
  -y, --force-yearly     Force yearly promotion.
  -k, --kill             Stop running backups.
  --deploy-agent [TG]    Deploy agent to target (user@host).
  --setup-remote [TG]    Wizard: SSH Setup, Duplicate Check, Deploy & Harden.
  --agent-mode           Run in Agent Mode.
  -h, --help             Show this help.
EOF
    exit 0
}

## @brief Main entry point for the Agent Mode.
agent_main() {
    local action=""
    local install_target_user=""

    check_dependencies
    check_rsync_capabilities

    while [ $# -gt 0 ]; do
        case $1 in
            --action) action="$2"; shift 2 ;;
            --client) CLIENT_NAME="$2"; validate_client_name "$CLIENT_NAME"; shift 2 ;;
            --retain-hourly) RETAIN_HOURLY=$(sanitize_int "$2"); shift 2 ;;
            --retain-daily) RETAIN_DAILY=$(sanitize_int "$2"); shift 2 ;;
            --retain-weekly) RETAIN_WEEKLY=$(sanitize_int "$2"); shift 2 ;;
            --retain-monthly) RETAIN_MONTHLY=$(sanitize_int "$2"); shift 2 ;;
            --retain-yearly) RETAIN_YEARLY=$(sanitize_int "$2"); shift 2 ;;
            --smart-purge-limit) SPACE_LOW_LIMIT_GB=$(sanitize_int "$2"); shift 2 ;;
            --smart-purge-slots) SMART_PURGE_SLOTS=$(sanitize_int "$2"); shift 2 ;;
            --user) install_target_user="$2"; shift 2 ;;
            --version) echo "$SCRIPT_VERSION"; exit 0 ;;
            --help|-h) echo "Snapshot Agent v$SCRIPT_VERSION"; exit 0 ;;
            --config|-c) load_config "$2"; shift 2 ;;
            --agent-mode) shift ;;
            --status) action="status"; shift ;;
            *) shift ;;
        esac
    done

    # Re-calculate Base Interval based on parsed/loaded retention settings
    BASE_INTERVAL=$(detect_base_interval)
    
    if [ -n "$CLIENT_NAME" ]; then
         LOGTAG="${LOGTAG}-${CLIENT_NAME}"
         case "$LOGFILE" in */snapshot-backup.log) LOGFILE="${LOGFILE%.log}-${CLIENT_NAME}.log" ;; esac
    fi
    
    case "$action" in
        prepare) do_prepare ;;
        commit) do_commit ;;
        purge) do_purge ;;
        status) do_status ;;
        check-job-done) do_check_job_done ;;
        check-storage) do_check_storage ;;
        install) do_install "$install_target_user" ;;
        version) echo "$SCRIPT_VERSION"; exit 0 ;;
        *) die "Unknown Agent Action: $action" ;;
    esac
}

## @brief Main entry point for the Client Mode.
client_main() {
    local custom_config=""
    local do_kill=false
    local do_status=false
    local do_desktop=false
    local show_conf=false
    local explicit_service=false
    local do_mount_cmd=false
    local do_umount_cmd=false
    local do_deploy_cmd=false
    local do_setup_cmd=false
    local do_install_cmd=false
    local do_is_running=false
    local do_is_job_done=false
    local do_has_storage=false
    
    local mount_path=""
    local mount_client=""
    local deploy_target=""
    local setup_target=""
    local install_user=""

    if [ $# -eq 0 ]; then RUN_MODE="SERVICE"; else RUN_MODE="INTERACTIVE"; fi

    for arg in "$@"; do
        if [ "$arg" = "--debug" ]; then DEBUG_MODE="true"; fi
    done
    local next_is_conf=false
    for arg in "$@"; do
        if [ "$next_is_conf" = true ]; then CONFIG_FILE="$arg"; next_is_conf=false; continue; fi
        if [ "$arg" = "-c" ] || [ "$arg" = "--config" ]; then next_is_conf=true; fi
    done

    load_config "$CONFIG_FILE"
    
    while [ $# -gt 0 ]; do
        case $1 in
            --show-config) show_conf=true; shift ;;
            --version) echo "Snapshot Backup Client v$SCRIPT_VERSION"; exit 0 ;;
            --is-running) do_is_running=true; shift ;;
            --is-job-done) do_is_job_done=true; shift ;;
            --has-storage) do_has_storage=true; shift ;;
            --timeout) NETWORK_TIMEOUT=$(sanitize_int "$2"); shift 2 ;;
            --status) do_status=true; shift ;;
            --desktop) do_desktop=true; shift ;;
            --verify|-v) FORCE_VERIFY=true; shift ;;
            -c|--config) shift 2 ;; 
            -f|--force-weekly) FORCE_WEEKLY=true; shift ;;
            -m|--force-monthly) FORCE_MONTHLY=true; shift ;;
            -y|--force-yearly) FORCE_YEARLY=true; shift ;;
            -k|--kill) do_kill=true; shift ;;
            -s|--service) explicit_service=true; shift ;;
            --mount) do_mount_cmd=true; mount_path="${2:-}"; if [ -z "$mount_path" ] || [ "${mount_path#-}" != "$mount_path" ]; then mount_path=""; else shift; fi; shift ;;
            --umount) do_umount_cmd=true; mount_path="${2:-}"; if [ -z "$mount_path" ] || [ "${mount_path#-}" != "$mount_path" ]; then mount_path=""; else shift; fi; shift ;;
            --client) mount_client="$2"; shift 2 ;;
            --deploy-agent) do_deploy_cmd=true; deploy_target="${2:-}"; if [ -z "$deploy_target" ] || [ "${deploy_target#-}" != "$deploy_target" ]; then deploy_target=""; else shift; fi; shift ;;
            --setup-remote) do_setup_cmd=true; setup_target="${2:-}"; if [ -z "$setup_target" ] || [ "${setup_target#-}" != "$setup_target" ]; then setup_target=""; else shift; fi; shift ;;
            --install) do_install_cmd=true; install_user="${2:-}"; if [ -z "$install_user" ] || [ "${install_user#-}" != "$install_user" ]; then install_user=""; else shift; fi; shift ;;
            --debug) shift ;;
            -h|--help) show_help ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [ "$explicit_service" = true ]; then RUN_MODE="SERVICE"; fi
    if [ "$do_kill" = true ]; then kill_active_backups; fi
    if [ "$show_conf" = true ]; then show_config; fi
    if [ "$do_status" = true ]; then show_status; exit 0; fi
    if [ "$do_desktop" = true ]; then status_desktop; exit 0; fi
    if [ "$do_is_running" = true ]; then check_is_running_cli; fi
    if [ "$do_is_job_done" = true ]; then check_is_job_done_cli; fi
    if [ "$do_has_storage" = true ]; then check_has_storage_cli; fi
    if [ "$do_deploy_cmd" = true ]; then do_deploy_agent "$deploy_target"; exit 0; fi
    if [ "$do_setup_cmd" = true ]; then do_setup_remote "$setup_target"; exit 0; fi
    if [ "$do_install_cmd" = true ]; then do_install "$install_user"; exit 0; fi
    if [ "$do_mount_cmd" = true ]; then do_mount "$mount_path" "$mount_client"; exit 0; fi
    if [ "$do_umount_cmd" = true ]; then do_umount "$mount_path"; exit 0; fi
    
    check_rsync_capabilities
    acquire_lock

    if [ "${DEEP_VERIFY_INTERVAL_DAYS:-0}" -gt 0 ] && [ "$FORCE_VERIFY" = false ]; then
         if [ ! -f "$LAST_VERIFY_FILE" ]; then
             log "INFO" "Deep Verify: No previous verification found. Forcing check."
             FORCE_VERIFY=true
         else
             local last_ts; last_ts=$(cat "$LAST_VERIFY_FILE" 2>/dev/null || echo "0")
             local now; now=$(date +%s)
             if [ $(( (now - last_ts) / 86400 )) -ge "$DEEP_VERIFY_INTERVAL_DAYS" ]; then
                 log "INFO" "Deep Verify: Interval expired. Forcing check."
                 FORCE_VERIFY=true
             fi
         fi
    fi
    if [ "$FORCE_VERIFY" = true ]; then RSYNC_EXTRA_OPTS="${RSYNC_EXTRA_OPTS:-} --checksum"; fi
    
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        run_backup_session "REMOTE"
    else 
        run_backup_session "LOCAL"
    fi
    log_summary
}

## @brief Entry point controller.
main() {
    # Initialize Global Start Time
    START_TIME=$(date +%s)

    case "${1:-}" in --agent-mode) AGENT_MODE=true ;; esac
    case "$(basename "$0")" in *snapshot-agent*) AGENT_MODE=true ;; esac
    
    if [ "$AGENT_MODE" = true ]; then agent_main "$@"; else client_main "$@"; fi
}

main "$@"