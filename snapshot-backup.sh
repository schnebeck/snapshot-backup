#!/bin/sh

# ==============================================================================
## @file    snapshot-backup.sh
## @brief   Unified Snapshot Backup Client & Agent (POSIX sh)
## @version 18.7
##
## @note    DEVIATION FROM STRICT POSIX:
##          This script utilizes the 'local' keyword for variable scoping.
##          This deviation is intentional to prevent global variable pollution
##          and improve maintainability in this complex codebase.
##
## @details This script implements a strict Calendar rotation policy.
##          It uses a unified Core Logic for both Local and Remote modes to ensure
##          consistency and support In-Place Updates.
##
## @producedby thorsten.schnebeck@gmx.net
## @writtenby Gemini AI V3.0 antigravity agent
## @reviewedby thorsten.schnebeck@gmx.net
##
## @license GPLv3
# ==============================================================================

set -u
export LC_ALL=C
umask 0077

# ==============================================================================
# 1. CONSTANTS & CONFIGURATION DEFAULTS
# ==============================================================================

SCRIPT_VERSION="18.7"
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

# Default Retention
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

SPACE_LOW_LIMIT_GB=0
SMART_PURGE_SLOTS=0
LOG_PROGRESS_INTERVAL=60
RSYNC_EXTRA_OPTS=""
DEEP_VERIFY_INTERVAL_DAYS="35"
ENABLE_NOTIFICATIONS=true
NETWORK_TIMEOUT=10
FORCE_VERIFY=false

# Hook state. _HOOKS_ARMED says a PRE hook may have set something up, so the
# POST hook is owed; _RUN_EXIT_CODE is what the POST hook is told.
_HOOKS_ARMED=false
_RUN_EXIT_CODE=1

# Hook commands, normally set in the config file.
PRE_RUN_CMD=""
PRE_RSYNC_CMD=""
POST_RUN_CMD=""

RSYNC_PROGRESS_OPTS=""
RSYNC_ACL_OPT=""
RSYNC_XATTR_OPT=""

# ==============================================================================
# 2. UTILITY FUNCTIONS
# ==============================================================================

## @brief Logs a message to file, stderr, and syslog.
## @param level Log level (INFO, WARN, ERROR, DEBUG)
## @param msg The message to log
log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts=$(date "+%Y-%m-%d %H:%M:%S")
    local clean_msg
    clean_msg=$(echo "$msg" | sed 's/\\e\[[0-9;]*m//g')
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
        if [ "$level" = "DEBUG" ] && [ "${DEBUG_MODE:-false}" != "true" ]; then return 0; fi
        if [ -t 1 ]; then
            case "$level" in
                ERROR) printf "\033[1;31m:: %s: %s\033[0m\n" "$level" "$msg" >&2 ;;
                WARN)  printf "\033[1;33m:: %s: %s\033[0m\n" "$level" "$msg" >&2 ;;
                INFO)  printf "\033[1;32m::\033[0m %s\n" "$msg" >&2 ;;
                DEBUG) printf "\033[1;34m:: [DEBUG]\033[0m %s\n" "$msg" >&2 ;;
                *)     printf ":: %s\n" "$msg" >&2 ;;
            esac
        else
            echo ":: [$level] $clean_msg" >&2
        fi
    fi

    if [ "$level" != "DEBUG" ]; then
        local prio="user.info"
        case "$level" in ERROR) prio="user.err" ;; WARN) prio="user.warning" ;; esac
        local safe_msg
        safe_msg=$(echo "$clean_msg" | cut -c 1-1000)
        logger -t "$LOGTAG" -p "$prio" -- "$safe_msg"
    fi
}

## @brief Logs an error and exits with status 1.
die() {
    log "ERROR" "$1"
    exit 1
}

## @brief Safely removes a directory or file.
safe_rm() {
    local target="$1"
    if [ -z "$target" ] || [ "$target" = "/" ]; then
        log "ERROR" "Refusing to rm -rf '$target'"
        return 1
    fi
    if [ -e "$target" ]; then
        rm -rf "$target"
    fi
}

## @brief Sanitizes input to ensure it is an integer.
sanitize_int() {
    local val=${1:-0}
    # Strict: Only digits allowed. No minus.
    val=$(echo "$val" | tr -cd '0-9')
    if [ -z "$val" ]; then
        echo "0"
    else
        echo "$val"
    fi
}

## @brief Runs a command with a timeout (compatible with busybox/coreutils).
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

## @brief Executes a command on the remote host via SSH.
run_remote_cmd() {
    ssh -p "$REMOTE_PORT" $REMOTE_SSH_OPTS -i "$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST" "$@"
}

## @brief Executes a remote command with a timeout.
run_remote_cmd_with_timeout() {
    local d="$1"
    shift
    compat_run_with_timeout "$d" ssh -p "$REMOTE_PORT" $REMOTE_SSH_OPTS -i "$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST" "$@"
}

# --- Date Abstraction ---
if date -d "@0" +%s >/dev/null 2>&1; then
    ## @brief Converts a timestamp to a formatted date string (GNU date).
    ts_to_date() { date -d "@$1" "$2" 2>/dev/null || echo "ERROR"; }
    ## @brief Parses a date string to a timestamp (GNU date).
    _parse_legacy_date() { date -d "$1" +%s 2>/dev/null || echo "0"; }
elif date -r 0 +%s >/dev/null 2>&1; then
    ## @brief Converts a timestamp to a formatted date string (BSD date).
    ts_to_date() { date -r "$1" "$2" 2>/dev/null || echo "ERROR"; }
    ## @brief Parses a date string to a timestamp (BSD date).
    _parse_legacy_date() { date -j -f "%Y-%m-%d %H:%M:%S" "$1" +%s 2>/dev/null || echo "0"; }
else
    ## @brief Fallback for incompatible date utilities.
    ts_to_date() { echo "ERROR: Date utility incompatible"; }
    ## @brief Fallback date parser.
    _parse_legacy_date() { echo "0"; }
fi

## @brief Reads a timestamp from a file and validates it. Returns 0 on failure.
## @warning DO NOT modify whitespace handling aggressively! 
##          Legacy timestamps like "YYYY-MM-DD HH:MM:SS" MUST retain internal spaces
##          to be parsed correctly by 'date'. Using `tr -d '[:space:]'` breaks this.
read_timestamp() {
    local f="$1"
    if [ ! -f "$f" ]; then echo "0"; return; fi
    
    local content
    read -r content < "$f" 2>/dev/null || true
    
    # 1. Try strict check first (Epoch timestamp, no spaces)
    if echo "$content" | grep -qE "^[0-9]+$"; then
        echo "$content"
        return
    fi
    
    # 2. Try cleanup (remove surrounding whitespace but KEEP internal spaces)
    local clean_content
    if command -v sed >/dev/null 2>&1; then
        clean_content=$(echo "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    else
        # Fallback: aggressive tr (only safe if no internal spaces needed)
        clean_content=$(echo "$content" | tr -d ' \t\n\r')
    fi
    
    # Check again if it's pure number after cleanup
    if echo "$clean_content" | grep -qE "^[0-9]+$"; then
        echo "$clean_content"
        return
    fi

    # 3. Fallback: Parse as Date (Legacy Format) using ORIGINAL content to preserve spaces
    local parsed
    parsed=$(_parse_legacy_date "$content")
    parsed=$(sanitize_int "$parsed")
    echo "$parsed"
}

## @brief Helper to parse quoted words in a line.
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
                    if [ -n "$word" ]; then
                        "$callback" "$word"
                    fi
                    ;;
            esac
        fi
    done
}

## @brief Iterates over a newline-separated list and calls callback for each item.
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

## @brief Returns 0 if the given UID should receive desktop notifications.
## Allows: graphical sessions (x11/wayland/mir) and lingering users with no
## active session (daemon may still be running). Blocks: SSH/tty-only sessions.
_has_graphical_session() {
    local uid="$1"
    local session_id stype has_sessions=false
    local sessions
    sessions=$(loginctl show-user "$uid" --property=Sessions --value 2>/dev/null)
    for session_id in $sessions; do
        has_sessions=true
        stype=$(loginctl show-session "$session_id" -p Type --value 2>/dev/null)
        case "$stype" in
            x11|wayland|mir) return 0 ;;
        esac
    done
    # No graphical session found: allow if lingering (no sessions at all),
    # block if only SSH/tty sessions are active (server context).
    [ "$has_sessions" = false ]
}

## @brief Sends a system notification if enabled.
notify() {
    local title="$1"
    local msg="$2"
    local urgency="${3:-normal}"

    if [ "$ENABLE_NOTIFICATIONS" != true ]; then return 0; fi

    (
        set +e
        if ! command -v notify-send >/dev/null 2>&1; then exit 0; fi

        if [ "$(id -u)" -ne 0 ]; then
            compat_run_with_timeout 5 notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
            exit $?
        fi

        local target_user=""
        local target_uid=""
        local cand_uid=""

        # Prefer SUDO_USER if it's a real (non-root) user with an active graphical session
        if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
            cand_uid=$(id -u "$SUDO_USER" 2>/dev/null)
            if [ -n "$cand_uid" ] && [ "$cand_uid" -ge 1000 ] 2>/dev/null \
               && [ -S "/run/user/$cand_uid/bus" ] \
               && _has_graphical_session "$cand_uid"; then
                target_user="$SUDO_USER"
                target_uid="$cand_uid"
            fi
        fi

        # Fallback: scan for any human user with an active graphical D-Bus session
        # (skips SSH-only sessions on servers where /run/user/*/bus may still exist)
        if [ -z "$target_user" ]; then
            for bus_socket in /run/user/*/bus; do
                [ -S "$bus_socket" ] || continue
                cand_uid=$(echo "$bus_socket" | sed 's|/run/user/\([0-9]*\)/bus|\1|')
                [ "$cand_uid" -ge 1000 ] 2>/dev/null || continue
                _has_graphical_session "$cand_uid" || continue
                target_user=$(id -nu "$cand_uid" 2>/dev/null) || continue
                target_uid="$cand_uid"
                break
            done
        fi

        [ -n "$target_user" ] || exit 0

        local dbus_addr="unix:path=/run/user/$target_uid/bus"
        # runuser switches user without sudo/PAM overhead; env passes DBUS address explicitly
        if command -v runuser >/dev/null 2>&1; then
            compat_run_with_timeout 5 runuser -u "$target_user" -- \
                env "DBUS_SESSION_BUS_ADDRESS=$dbus_addr" \
                notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
        else
            compat_run_with_timeout 5 su -c \
                "DBUS_SESSION_BUS_ADDRESS='$dbus_addr' notify-send -u '$urgency' -a 'Snapshot Backup' '$title' '$msg'" \
                "$target_user" 2>/dev/null
        fi
    ) || true
}

log_startup_summary() {
    log "INFO" "--- Starting Backup Session (v$SCRIPT_VERSION) ---"
    
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        log "INFO" "Target Remote: $REMOTE_USER@$REMOTE_HOST:$REMOTE_STORAGE_ROOT"
        log "INFO" "Client ID:     ${CLIENT_NAME:-$(hostname)}"
        
        if [ -n "$BACKUP_ROOT" ] && [ "$BACKUP_ROOT" != "/" ]; then
             log "INFO" "Local Mount:   $BACKUP_ROOT (only used for --mount actions)"
        fi
    else
        log "INFO" "Target Local:  $BACKUP_ROOT"
    fi

    local space=""
    if [ "$BACKUP_MODE" = "LOCAL" ] && [ -d "$BACKUP_ROOT" ]; then
         space=$(df -hP "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')
         log "INFO" "Disk Space:    $space available."
    fi

    log "INFO" "Retention:     H=$RETAIN_HOURLY D=$RETAIN_DAILY W=$RETAIN_WEEKLY M=$RETAIN_MONTHLY Y=$RETAIN_YEARLY"
}

# ==============================================================================
# 3. CORE SHARED LOGIC
# ==============================================================================

## @brief Constructs the full path for a given interval and index.
get_interval_path() { echo "$BACKUP_ROOT/$1.${2:-0}"; }

## @brief Finds the highest index for a given interval.
get_max_index() {
    local int="$1"
    # Robustly fetch max index. Return -1 if not found.
    # We grep digits to be safe, sort reverse numeric, take top.
    local res
    res=$(find "$BACKUP_ROOT" -maxdepth 1 -name "${int}.*" -type d 2>/dev/null | sed "s/^.*${int}\.//" | grep -E '^[0-9]+$' | sort -rn | head -n 1)
    
    if [ -z "$res" ]; then
        echo "-1"
    else
        echo "$res"
    fi
}

## @brief Retrieves the retention count for a given interval.
get_retention() {
    # Replaced 'tr' with native case for robustness and speed
    local val
    case "$1" in
        hourly) val="${RETAIN_HOURLY:-0}" ;;
        daily)  val="${RETAIN_DAILY:-0}" ;;
        weekly) val="${RETAIN_WEEKLY:-0}" ;;
        monthly) val="${RETAIN_MONTHLY:-0}" ;;
        yearly) val="${RETAIN_YEARLY:-0}" ;;
        *) val="0" ;;
    esac
    echo "$val"
}

## @brief Detects the base interval (e.g. daily, hourly) based on retention.
detect_base_interval() {
    for i in $INTERVALS; do
        local r
        r=$(get_retention "$i")
        if [ "$r" -gt 0 ]; then
            echo "$i"
            return
        fi
    done
    echo "daily"
}

## @brief Gets the next interval in the hierarchy (e.g. daily -> weekly).
get_next_interval() {
    local current="$1"
    local found=false
    for i in $INTERVALS; do
        # Checks if retention > 0. If 0, the interval is skipped (gap closing logic).
        if [ "$found" = true ] && [ "$(get_retention "$i")" -gt 0 ]; then
            echo "$i"
            return
        fi
        [ "$i" = "$current" ] && found=true
    done
    echo "none"
}

## @brief Generates a sortable date string from a timestamp.
get_sortable_date() {
    local interval="$1"
    local ts="${2:-0}"
    ts=$(sanitize_int "$ts")
    
    if [ "$ts" -eq 0 ]; then echo "0"; return; fi

    # Promotion compares these numerically, so each one must grow with time and
    # name exactly one period. Weekly is the ISO year plus ISO week. Before 18.7
    # it was "%Y%m%V": a week across a month boundary had two signatures and got
    # two weekly snapshots, and ISO week 53 in early January compared as newer
    # than every January week, so nothing was promoted until February. Daily and
    # hourly carried the week number in the middle and broke the same way.
    # "%Y%W" is the fallback for a date without %G: also monotonic, its weeks
    # only split at New Year.
    local week_fmt="%G%V"
    case "$(ts_to_date "$ts" "+%G%V")" in ''|*[!0-9]*) week_fmt="%Y%W" ;; esac
    
    case "$interval" in
        hourly)  ts_to_date "$ts" "+%Y%m%d%H" ;;
        daily)   ts_to_date "$ts" "+%Y%m%d" ;;
        weekly)  ts_to_date "$ts" "+$week_fmt" ;;
        monthly) ts_to_date "$ts" "+%Y%m" ;;
        yearly)  ts_to_date "$ts" "+%Y" ;;
        *)       echo "0" ;;
    esac
}

## @brief Checks if a backup timestamp belongs to a previous period.
is_backup_older_than_current_period() {
    local int="$1"
    local old_ts="$2"
    local now_ts="$3"
    
    old_ts=$(sanitize_int "$old_ts")
    now_ts=$(sanitize_int "$now_ts")
    
    local old_sig
    old_sig=$(get_sortable_date "$int" "$old_ts")
    
    local now_sig
    now_sig=$(get_sortable_date "$int" "$now_ts")
    
    if [ "$old_sig" != "$now_sig" ]; then
        echo "true"
    else
        echo "false"
    fi
}

## @brief Renumbers backup directories to remove gaps.
consolidate_directory_indices() {
    local int="$1"
    [ ! -d "$BACKUP_ROOT" ] && return
    
    local target_index=0
    find "$BACKUP_ROOT" -maxdepth 1 -name "${int}.*" -type d ! -name "*.tmp" 2>/dev/null | sed "s/^.*${int}\.//" | grep -E "^[0-9]+$" | sort -n | while read current_index; do
        if [ -n "$current_index" ]; then
            if [ "$current_index" -ne "$target_index" ]; then
                log "DEBUG" "Consolidating $int: $current_index -> $target_index"
                mv "$BACKUP_ROOT/$int.$current_index" "$BACKUP_ROOT/$int.$target_index"
            fi
            target_index=$((target_index+1))
        fi
    done
}

rotate_period_up() {
    local int="$1"
    local raw_max
    raw_max=$(get_max_index "$int")
    
    if [ "$raw_max" = "-1" ]; then return; fi
    
    local max_idx
    max_idx=$(sanitize_int "$raw_max")
    
    # NEU: Info, dass wir rotieren
    log "INFO" "Rotating interval '$int': Shifting $max_idx existing snapshots up..."

    local i=$max_idx
    while [ "$i" -ge 0 ]; do
        if [ -d "$BACKUP_ROOT/$int.$i" ]; then
            # Optional: Jede einzelne Verschiebung loggen? 
            # Das wären bei 30 Dailies 30 Zeilen. Vielleicht zu viel.
            # log "DEBUG" "mv $int.$i -> $int.$((i+1))" 
            mv "$BACKUP_ROOT/$int.$i" "$BACKUP_ROOT/$int.$((i+1))"
        fi
        i=$((i-1))
    done
}

## @brief Prepares the target directory for a new backup logic.
core_prepare_backup_target() {
    local int="$1"
    mkdir -p "$BACKUP_ROOT"
    chmod 700 "$BACKUP_ROOT"
    
    # 1. Clean indices
    for i in $INTERVALS; do
        consolidate_directory_indices "$i"
    done
    
    local target_0
    target_0=$(get_interval_path "$int" 0)
    local target_tmp="$target_0.tmp"
    
    # Check for and clean stale tmp
    if [ -d "$target_tmp" ]; then
        local tmp_ts=0
        if command -v stat >/dev/null 2>&1; then
            tmp_ts=$(stat -c %Y "$target_tmp" 2>/dev/null || echo "0")
        fi
        
        tmp_ts=$(sanitize_int "$tmp_ts")
        
        if [ "$tmp_ts" -eq 0 ]; then
             tmp_ts=$(date -r "$target_tmp" +%s 2>/dev/null || echo "0")
             tmp_ts=$(sanitize_int "$tmp_ts")
        fi
        
        local now_ts
        now_ts=$(date +%s)
        now_ts=$(sanitize_int "$now_ts")
        
        local age
        age=$(( ${now_ts:-0} - ${tmp_ts:-0} ))
        
        if [ "${age:-0}" -gt 86400 ] && [ "${tmp_ts:-0}" -ne 0 ]; then
             log "WARN" "Found stale temporary backup '$target_tmp'. Removing."
             safe_rm "$target_tmp"
        fi
    fi

    # Decide: Initial or Update
    if [ ! -d "$target_0" ]; then
        log "INFO" "No valid backup found in ($int). Preparing INITIAL backup at .0"
        mkdir -p "$target_0"
        chmod 700 "$target_0"
        echo "$target_0"
        return
    fi

    local last_ts
    last_ts=$(read_timestamp "$target_0/$TIMESTAMP_FILE")
    last_ts=$(sanitize_int "$last_ts")
    
    local is_older
    is_older=$(is_backup_older_than_current_period "$int" "$last_ts" "$START_TIME")
    
    if [ "$is_older" = "false" ]; then
        log "INFO" "Current backup ($int.0) is still valid. Updating IN-PLACE."
        echo "$target_0"
    else
        log "INFO" "Current backup ($int.0) is old. Preparing ROTATION at .0.tmp"
        if [ -d "$target_tmp" ]; then
            safe_rm "$target_tmp"
        fi
        cp -al "$target_0" "$target_tmp"
        chmod 700 "$target_tmp"
        echo "$target_tmp"
    fi
}

## @brief Finalizes the backup by writing timestamps and populating other intervals.
core_commit_backup() {
    local int="$1"
    local target_used="$2"
    local target_0
    target_0=$(get_interval_path "$int" 0)
    
    # 1. Commit/Rotate logic
    if [ "${target_used%.tmp}" != "$target_used" ]; then
        log "INFO" "Commit: Rotating and moving .tmp to .0"
        rotate_period_up "$int"
        mv "$target_used" "$target_0"
    else
        log "INFO" "Commit: In-Place update completed."
    fi
    
    # 2. Timestamp & Permissions for the primary target
    if [ -d "$target_0" ]; then
        date +%s > "$target_0/$TIMESTAMP_FILE"
        chmod 700 "$target_0"
    fi

    # 3. FORCE POPULATE (The "Must Exist" Rule)
    # Iterate through ALL defined intervals. If an interval is active (Retain > 0)
    # but currently empty (missing .0), immediately seed it from the current backup.
    for check_int in $INTERVALS; do
        if [ "$(get_retention "$check_int")" -gt 0 ]; then
            local check_path
            check_path=$(get_interval_path "$check_int" 0)
            
            # Is the .0 folder missing?
            if [ ! -d "$check_path" ]; then
                log "INFO" ">>> SEEDING REQUIRED: Interval '$check_int' is empty but active."
                log "INFO" ">>> Action: Creating $check_int.0 as a hardlink copy of $int.0"                
                # Create Hardlink Copy from the just-finished backup
                # This recursively links EVERYTHING, including the timestamp file.
                cp -al "$target_0" "$check_path"
                
                # Ensure permissions (timestamp file is already there via hardlink)
                chmod 700 "$check_path"
            fi
        fi
    done
}

## @brief Evaluates promotion for a single backup slot.
## @param 1 Source Interval (e.g. daily)
## @param 2 Source Index (e.g. 0)
## @param 3 Target Interval (e.g. weekly)
## @param 4 Base Interval (The shortest interval, e.g. hourly/daily)
check_and_promote_single_item() {
    local src_int="$1"
    local src_idx="$2"
    local tgt_int="$3"
    local base_int="$4"
    
    local src_path="$BACKUP_ROOT/$src_int.$src_idx"
    if [ ! -d "$src_path" ]; then return 0; fi

    # --- RULE 1: ADMIN VIEW PROTECTION ---
    # The newest snapshot (.0) of the base interval is untouchable.
    # It serves as the immediate restore point and status indicator.
    if [ "$src_int" = "$base_int" ] && [ "$src_idx" -eq 0 ]; then
        return 0
    fi

    # If no target defined (e.g. yearly has no parent), skip promotion logic.
    if [ -z "$tgt_int" ]; then return 0; fi

    local tgt_path_0="$BACKUP_ROOT/$tgt_int.0"
    local src_ts
    src_ts=$(read_timestamp "$src_path/$TIMESTAMP_FILE")
    local promote=false
    
    # --- RULE 2: PROMOTION CHECK ---
    # Condition A: Seeding (Target does not exist)
    if [ ! -d "$tgt_path_0" ]; then
        log "INFO" "Promotion [$src_int.$src_idx -> $tgt_int.0]: Initializing empty target."
        promote=true
    else
        # Condition B: Calendar Check
        local tgt_ts
        tgt_ts=$(read_timestamp "$tgt_path_0/$TIMESTAMP_FILE")
        local src_sig
        src_sig=$(get_sortable_date "$tgt_int" "$src_ts")
        local tgt_sig
        tgt_sig=$(get_sortable_date "$tgt_int" "$tgt_ts")
        
        if [ "$src_sig" -gt "$tgt_sig" ]; then
            log "INFO" "Promotion [$src_int.$src_idx -> $tgt_int.0]: New period detected ($src_sig > $tgt_sig)."
            promote=true
        fi
    fi

    if [ "$promote" = "true" ]; then
        # Condition C: Last Man Standing Check
        # (Only relevant for non-base intervals or indices > 0, since base.0 is protected above)
        if [ "$src_idx" -eq 0 ] && [ ! -d "$BACKUP_ROOT/$src_int.1" ]; then
            log "INFO" "Promotion postponed: $src_int.$src_idx is the only remaining snapshot."
            return 0
        fi

        rotate_period_up "$tgt_int"
        
        log "INFO" "Promoting via MOVE (Cleaning up $src_path)."
        mv "$src_path" "$tgt_path_0"
        
        if [ ! -f "$tgt_path_0/$TIMESTAMP_FILE" ] && [ -n "$src_ts" ]; then
            echo "$src_ts" > "$tgt_path_0/$TIMESTAMP_FILE"
        fi
        chmod 700 "$tgt_path_0"
        
        return 1 # Status: Promoted
    fi

    return 0 # Status: Kept
}

## @brief Deletes oldest daily backups if disk space is low.
apply_smart_retention_policy() {
    [ "$SPACE_LOW_LIMIT_GB" -le 0 ] || [ ! -d "$BACKUP_ROOT" ] && return
    
    local avail_gb
    avail_gb=$(df -P "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
    avail_gb=$((avail_gb / 1024 / 1024))
    
    if [ "$avail_gb" -lt "$SPACE_LOW_LIMIT_GB" ]; then
        log "WARN" "Smart purge triggered: ${avail_gb}GB available."
        RETAIN_DAILY=$((RETAIN_DAILY - SMART_PURGE_SLOTS))
        [ "$RETAIN_DAILY" -lt 1 ] && RETAIN_DAILY=1
    fi
}

## @brief Frees space before a transfer by removing the oldest base snapshots.
## Runs before the target is prepared, in both modes. A full target makes the
## transfer fail, and a purge that only runs after a successful transfer then
## never runs at all: a relay sat at 610 MB free for eight months this way,
## failing every night with "Broken pipe". Only the base interval is touched,
## at most SMART_PURGE_SLOTS snapshots, and never $int.0 - weekly and monthly
## history is not traded for space without someone deciding it.
make_room_before_backup() {
    local int="$1"
    [ "${SPACE_LOW_LIMIT_GB:-0}" -gt 0 ] && [ -d "$BACKUP_ROOT" ] || return 0

    local slots="${SMART_PURGE_SLOTS:-0}"
    local need_kb=$((SPACE_LOW_LIMIT_GB * 1024 * 1024))
    local avail_kb max_idx
    while :; do
        avail_kb=$(df -P "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
        avail_kb=$(sanitize_int "$avail_kb")
        [ "$avail_kb" -ge "$need_kb" ] && return 0

        if [ "$slots" -le 0 ]; then
            log "WARN" "Low space: $((avail_kb / 1024)) MB free, limit ${SPACE_LOW_LIMIT_GB} GB. No purge slots left (SMART_PURGE_SLOTS=${SMART_PURGE_SLOTS:-0})."
            return 0
        fi
        max_idx=$(get_max_index "$int")
        if [ "$max_idx" = "-1" ] || [ "$(sanitize_int "$max_idx")" -lt 1 ]; then
            log "WARN" "Low space: $((avail_kb / 1024)) MB free, limit ${SPACE_LOW_LIMIT_GB} GB. Only $int.0 is left, which is never purged."
            return 0
        fi
        max_idx=$(sanitize_int "$max_idx")
        log "WARN" "Smart purge: $((avail_kb / 1024)) MB free, limit ${SPACE_LOW_LIMIT_GB} GB. Removing $int.$max_idx before the transfer."
        safe_rm "$BACKUP_ROOT/$int.$max_idx"
        slots=$((slots - 1))
    done
}

## @brief Deletes backups that exceed the configured retention limit.
enforce_retention_limit() {
    local int="$1"
    local limit
    limit=$(get_retention "$int")
    
    # Safety check: Never delete everything. Assume 0 means 'keep all' or 'disabled interval' logic handled elsewhere.
    if [ "$limit" -le 0 ]; then return; fi
    
    local max_idx
    max_idx=$(get_max_index "$int")
    
    if [ "$max_idx" != "-1" ]; then
        max_idx=$(sanitize_int "$max_idx")
        
        # Delete everything strictly greater than or equal to the limit.
        # Example: Limit 7. Indices 0..6 allowed. Index 7+ deleted.
        local i=$max_idx
        while [ "$i" -ge "$limit" ]; do
            local path="$BACKUP_ROOT/$int.$i"
            if [ -d "$path" ]; then
                log "INFO" "Retention [$int]: Removing overflow backup $int.$i (Limit: $limit)"
                safe_rm "$path"
            fi
            i=$((i-1))
        done
    fi
}

## @brief Executes strict chain promotion (recursive propagation from bottom to top).
core_perform_all_promotions() {
    log "DEBUG" "Starting Strict-Chain Promotion..."
    
    apply_smart_retention_policy
    
    for current_int in $INTERVALS; do
        local current_retain
        current_retain=$(get_retention "$current_int")
        
        if [ "$current_retain" -le 0 ]; then
            continue
        fi

        local next_int
        next_int=$(get_next_interval "$current_int")
        [ "$next_int" = "none" ] && next_int=""
        
        local max_idx
        max_idx=$(get_max_index "$current_int")
        
        # 1. PROMOTION PHASE (Reverse Loop)
        if [ "$max_idx" != "-1" ]; then
            max_idx=$(sanitize_int "$max_idx")
            local i=$max_idx
            
            while [ "$i" -ge 0 ]; do
                # HIER: Übergebe BASE_INTERVAL als 4. Parameter
                check_and_promote_single_item "$current_int" "$i" "$next_int" "$BASE_INTERVAL"
                i=$((i-1))
            done
            
            # 2. CONSOLIDATION PHASE
            consolidate_directory_indices "$current_int"
            
            # 3. RETENTION PHASE
            enforce_retention_limit "$current_int"
        fi
    done
}

# ==============================================================================
# 4. EXECUTION FLOWS
# ==============================================================================

## @brief Checks available rsync features (progress, ACLs, xattrs).
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

## @brief Wrapper for rsync with retry logic (Remote only).
run_with_retry() {
    local max_retries=3
    local cooldown_time=300
    local failures=0
    local exit_code=0
    
    while true; do
        local start_ts
        start_ts=$(date +%s)
        
        run_monitored_rsync "$@"
        exit_code=$?
        
        # 0=Success, 24=Vanished files (Success for backup)
        if [ "$exit_code" -eq 0 ] || [ "$exit_code" -eq 24 ]; then
            return "$exit_code"
        fi
        
        local end_ts
        end_ts=$(date +%s)
        local duration=$((end_ts - start_ts))
        
        if [ "$duration" -ge "$cooldown_time" ]; then
            log "WARN" "Rsync failed after $duration sec (stable run). Reducing failure count."
            if [ "$failures" -gt 0 ]; then
                failures=$((failures - 1))
            fi
        else
            failures=$((failures + 1))
        fi
        
        if [ "$failures" -ge "$max_retries" ]; then
            log "ERROR" "Too many consecutive failures ($failures). Aborting."
            return "$exit_code"
        fi
        
        log "WARN" "Retrying in 30s... (Consecutive Failures: $failures/$max_retries)"
        sleep 30
    done
}

## @brief Runs rsync and logs progress periodically.
run_monitored_rsync() {
    local last_log_time=0
    local log_interval=${LOG_PROGRESS_INTERVAL:-60}
    local status_file
    status_file=$(mktemp 2>/dev/null) || { status_file="/tmp/snapshot_rsync_status.$$.$(date +%s)"; : > "$status_file"; }
    
    ("$@" --timeout=300 $RSYNC_PROGRESS_OPTS 2>&1; echo $? > "$status_file") | while IFS= read -r line; do
            if echo "$line" | grep -q "[0-9]%[ ]"; then
                local now
                now=$(date +%s)
                if [ $((now - last_log_time)) -ge "$log_interval" ]; then
                     [ "${ENABLE_NOTIFICATIONS:-false}" = true ] && notify "Snapshot Backup" "Progress: $(echo "$line" | grep -o "[0-9]*%" | head -1)" "low"
                     last_log_time=$now
                fi
            else
                # Anchored on purpose. Unanchored "denied", "failed:" and
                # "fatal:" also match rsync's ordinary file listing: a backup
                # containing AccessDeniedException.php or
                # access_denied_traffic_node.py logged hundreds of errors for a
                # run that succeeded, which teaches people to ignore the log.
                # rsync prefixes its own diagnostics, so anchoring loses
                # nothing; "IO error" is added because rsync writes that one
                # without a prefix and it is real.
                #
                # "rsync warning: ... vanished" is deliberately absent: files
                # disappearing while a live filesystem is copied is normal, and
                # reporting it would produce noise every night.
                if echo "$line" | grep -qiE "^rsync(:| error)|^IO error|^ERROR:|^fatal:|: Permission denied|: No space left"; then
                    log "ERROR" "$line"
                else
                    log "DEBUG" "$line"
                fi
            fi
    done
    
    # No status means rsync's exit was never recorded - the subshell was killed.
    # That is not a success; before 18.7 it counted as one.
    local rsync_exit
    rsync_exit=$(cat "$status_file" 2>/dev/null)
    rm -f "$status_file"
    case "$rsync_exit" in ''|*[!0-9]*) log "ERROR" "rsync ended without an exit status."; rsync_exit=255 ;; esac
    
    if [ "$rsync_exit" -ne 0 ] && [ "$rsync_exit" -ne 24 ]; then
        log "ERROR" "Rsync failed with code $rsync_exit"
    fi
    return "$rsync_exit"
}

## @brief Generates a temporary exclusion file from patterns.
create_exclude_list() {
    if command -v mktemp >/dev/null 2>&1; then
        TEMP_EXCLUDE_FILE=$(mktemp)
    else
        TEMP_EXCLUDE_FILE="/tmp/snapshot_exclude_$$.$(date +%s)"
        touch "$TEMP_EXCLUDE_FILE"
        chmod 600 "$TEMP_EXCLUDE_FILE"
    fi
    
    _append() { echo "$1" >> "$TEMP_EXCLUDE_FILE"; }
    iterate_list "$EXCLUDE_PATTERNS" _append
}

## @brief Checks if source directories are safe to backup (not recursive).
check_path_safety() {
    if [ "$BACKUP_MODE" = "REMOTE" ]; then return 0; fi
    iterate_list "$SOURCE_DIRS" _check_single_path_safety
}

## @brief Internal check for a single source path.
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
                die "SAFETY ERROR: Backup destination '$BACKUP_ROOT' is inside source '$src' and not excluded."
            fi
            ;;
    esac
}

## @brief Core logic for executing backup of all sources.
core_backup_execution() {
    local _CTX_MODE="$1"
    local _CTX_DEST_BASE="$2"
    local _CTX_RSYNC_OPTS="$3"
    local _CTX_RAW_REMOTE_BASE="$4"
    local _CTX_SSH_CMD_OPTS="${5:-}"
    local _CTX_VERIFY_STATUS=0

    # After the target is prepared and before a single file is read. This is
    # the point an LVM snapshot or a filesystem freeze wants: the rotation that
    # runs before it can take ten minutes on a large chain, and a snapshot held
    # open that long collects changes in its copy-on-write area for nothing.
    if ! run_hook "PRE_RSYNC_CMD" "${PRE_RSYNC_CMD:-}"; then
        die "PRE_RSYNC_CMD failed - not backing up. A source that was meant to be frozen and is not would be copied as if it were."
    fi

    create_exclude_list
    
    _exec_item() {
        local src="$1"
        [ ! -e "$src" ] && return
        
        # 0 and 24 (files vanished while being read) are both a complete
        # copy of a live filesystem; anything else is not. A plain "if !"
        # counted 24 as a failure, and the caller then ignored the result.
        local rc=0
        if [ "$_CTX_MODE" = "REMOTE" ]; then
             run_with_retry rsync $_CTX_RSYNC_OPTS -e "$_CTX_SSH_CMD_OPTS" --exclude-from="$TEMP_EXCLUDE_FILE" -R "$src" "$_CTX_DEST_BASE/" || rc=$?
        else
             # -R, as in REMOTE mode: the same tree comes out, and an absolute
             # exclude like "/var/lib/x" means the real path. Without it the
             # transfer root was the source directory, and for any source other
             # than "/" such a pattern silently matched nothing.
             run_monitored_rsync rsync $_CTX_RSYNC_OPTS --exclude-from="$TEMP_EXCLUDE_FILE" -R "$src" "$_CTX_DEST_BASE/" || rc=$?
        fi
        case "$rc" in 0|24) ;; *) _CTX_VERIFY_STATUS=1 ;; esac
    }
    
    iterate_list "$SOURCE_DIRS" _exec_item
    
    if [ "$_CTX_MODE" = "LOCAL" ]; then
        _exec_mp() {
            local mp="$1"
            local rel="${mp#/}"
            [ -n "$rel" ] && mkdir -p "$_CTX_DEST_BASE/$rel" 2>/dev/null || true
        }
        iterate_list "$EXCLUDE_MOUNTPOINTS" _exec_mp
    fi
    
    rm -f "$TEMP_EXCLUDE_FILE"
    return "$_CTX_VERIFY_STATUS"
}

## @brief Orchestrates the local backup process.
_perform_local_backup_logic() {
    local int="$1"
    check_path_safety
    make_room_before_backup "$int"
    
    local target_path
    target_path=$(core_prepare_backup_target "$int")
    
    local r_opts="-aH $RSYNC_ACL_OPT $RSYNC_XATTR_OPT --delete --numeric-ids -x --stats"
    [ -n "${RSYNC_EXTRA_OPTS:-}" ] && r_opts="$r_opts $RSYNC_EXTRA_OPTS"
    
    local v_status=0
    if ! core_backup_execution "LOCAL" "$target_path" "$r_opts" "" ""; then
        v_status=1
    fi
    
    if [ "$v_status" -eq 0 ]; then
        [ "$FORCE_VERIFY" = true ] && record_verify_done
        core_commit_backup "$int" "$target_path"
        core_perform_all_promotions
        log "INFO" "Backup Summary: Success."
    else
        log "ERROR" "Backup failed. Cleaning up temp files."
        [ "${target_path%.tmp}" != "$target_path" ] && safe_rm "$target_path"
        # Exit non-zero: returning here reported success to cron, systemd
        # and POST_RUN_CMD alike, and a failing backup went unnoticed.
        exit 1
    fi
}

## @brief Orchestrates the remote backup process via agent.
_perform_remote_backup_logic() {
    if ! test_remote_connection; then die "Server unreachable."; fi
    check_agent_version
    
    local c_opts
    c_opts="$(get_retention_args)"

    # The agent reads no config of its own, so it only knows what it is told.
    # An agent older than 18.7 skips options it does not know.
    local p_opts=""
    [ "$SPACE_LOW_LIMIT_GB" -gt 0 ] && p_opts="--smart-purge-limit $SPACE_LOW_LIMIT_GB --smart-purge-slots $SMART_PURGE_SLOTS"
    
    local target_suffix
    target_suffix=$(run_remote_cmd "$REMOTE_AGENT --action prepare --client $CLIENT_NAME $c_opts $p_opts") || die "Remote preparation failed."
    target_suffix=$(echo "$target_suffix" | grep -E "^${BASE_INTERVAL}\.0(\.tmp)?$")
    if [ -z "$target_suffix" ]; then die "Invalid remote target received."; fi
    
    local t_ssh="$REMOTE_USER@$REMOTE_HOST:$REMOTE_STORAGE_ROOT/$CLIENT_NAME/$target_suffix"
    local t_raw_unused="$REMOTE_STORAGE_ROOT/$CLIENT_NAME/$target_suffix" 
    local ssh_cmd="ssh -p $REMOTE_PORT $REMOTE_SSH_OPTS -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -i $REMOTE_KEY"
    
    local r_opts="-avzH $RSYNC_ACL_OPT $RSYNC_XATTR_OPT --numeric-ids --delete --stats -x"
    [ -n "${RSYNC_EXTRA_OPTS:-}" ] && r_opts="$r_opts $RSYNC_EXTRA_OPTS"
    
    local v_status=0
    if ! core_backup_execution "REMOTE" "$t_ssh" "$r_opts" "$t_raw_unused" "$ssh_cmd"; then
        v_status=1
    fi

    # A failed transfer must not be committed. The commit writes the
    # timestamp, and a half-transferred tree with a timestamp is
    # indistinguishable from a good snapshot - it would rotate on as one.
    if [ "$v_status" -ne 0 ]; then
        die "Transfer failed - not committing. The last complete snapshot stays as it is."
    fi
    
    run_remote_cmd "$REMOTE_AGENT --action commit --client $CLIENT_NAME $c_opts" || exit 1
    [ "$FORCE_VERIFY" = true ] && record_verify_done
    
    run_remote_cmd "$REMOTE_AGENT --action purge --client $CLIENT_NAME $c_opts $p_opts" || exit 1
    
    log "INFO" "Backup Summary: Success."
}

## @brief Notes that a --checksum run completed, so the next is due in DEEP_VERIFY_INTERVAL_DAYS.
## Before 18.7 only LOCAL mode wrote this. A REMOTE client never found the
## stamp, counted from 1970 and verified every byte on both sides every night.
record_verify_done() {
    mkdir -p "$(dirname "$LAST_VERIFY_FILE")"
    date +%s > "$LAST_VERIFY_FILE"
}

## @brief Helper to generate retention arguments for agent calls.
get_retention_args() {
    echo "--retain-hourly $RETAIN_HOURLY --retain-daily $RETAIN_DAILY --retain-weekly $RETAIN_WEEKLY --retain-monthly $RETAIN_MONTHLY --retain-yearly $RETAIN_YEARLY"
}

# ==============================================================================
# 5. AGENT INTERFACE
# ==============================================================================

## @brief Serialises the agent actions that rename a client's snapshots.
## Before 18.7 prepare wrote a lock file and nothing ever read it. The lock is a
## directory (mkdir is atomic) holding the PID; a holder that no longer runs is
## stale and removed. AGENT_LOCK_WAIT seconds of waiting, then the action fails.
agent_lock() {
    local l="$AGENT_LOCK_DIR/$CLIENT_NAME.lockd" holder waited=0 wait_max
    wait_max=$(sanitize_int "${AGENT_LOCK_WAIT:-120}")
    mkdir -p "$AGENT_LOCK_DIR"
    while ! mkdir "$l" 2>/dev/null; do
        holder=$(cat "$l/pid" 2>/dev/null)
        # no PID after a few seconds: the holder died between mkdir and writing it
        if { [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; } || { [ -z "$holder" ] && [ "$waited" -ge 5 ]; }; then
            log "WARN" "Removing stale agent lock of '$CLIENT_NAME' (PID ${holder:-none})."
            rm -rf "$l"
            continue
        fi
        [ "$waited" -ge "$wait_max" ] && die "Another action for '$CLIENT_NAME' is running (PID ${holder:-?}). Gave up after ${wait_max}s."
        sleep 1
        waited=$((waited + 1))
    done
    echo $$ > "$l/pid"
    AGENT_HELD_LOCK="$l"
}

## @brief Removes agent lock file on exit.
agent_cleanup() {
    if [ -n "${AGENT_HELD_LOCK:-}" ] && [ "$(cat "$AGENT_HELD_LOCK/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$AGENT_HELD_LOCK"
    fi
    if [ -n "${CLIENT_NAME:-}" ] && [ -d "$AGENT_LOCK_DIR" ]; then
        local lf="$AGENT_LOCK_DIR/$CLIENT_NAME.lock"
        if [ -f "$lf" ]; then
            local lp
            lp=$(cat "$lf" 2>/dev/null)
            if [ "$lp" = "$$" ]; then
                rm -f "$lf"
            fi
        fi
    fi
}

## @brief Validates client name against path traversal/invalid chars.
validate_client_name() {
    local n="$1"
    [ -z "$n" ] && die "No client name."
    echo "$n" | grep -q "[^a-zA-Z0-9._-]" && die "Invalid client name."
    case "$n" in
        *".."*|*"/"*) die "Security Error: Path traversal.";;
    esac
}

## @brief Main entry point for Agent mode operations.
agent_main() {
    for arg in "$@"; do
        if [ "$arg" = "--version" ]; then echo "$SCRIPT_VERSION"; exit 0; fi
    done

    local action=""
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
            --key-blob) KEY_BLOB="$2"; shift 2 ;;
            --config|-c) load_config "$2"; shift 2 ;;
            --agent-mode) shift ;;
            --version) echo "$SCRIPT_VERSION"; exit 0 ;;
            *) shift ;;
        esac
    done
    
    case "$action" in
        version) echo "$SCRIPT_VERSION"; exit 0 ;;
        install) do_install_agent; exit 0 ;;
        lock-key) do_lock_key "${CLIENT_NAME:-}" "${KEY_BLOB:-}"; exit 0 ;;
        "") die "Error: No action specified." ;;
    esac

    [ -n "${CLIENT_NAME:-}" ] && {
        case "$LOGFILE" in */snapshot-backup.log) LOGFILE="${LOGFILE%.log}-${CLIENT_NAME}.log" ;; esac
        LOGTAG="${LOGTAG}-${CLIENT_NAME}"
    }
    
    BACKUP_ROOT="$BASE_STORAGE_PATH/${CLIENT_NAME:-unknown}"
    
    if [ ! -d "$BACKUP_ROOT" ]; then
        log "INFO" "Creating new client root: $BACKUP_ROOT"
        log "DEBUG" "used by action: $action"
        mkdir -p "$BACKUP_ROOT"
    else
        for snap_dir in "$BACKUP_ROOT"/*; do
            if [ -d "$snap_dir" ]; then
                # chmod ist schnell bei Verzeichnissen (Metadaten-Operation)
                chmod 700 "$snap_dir"
            fi
        done
    fi
    chmod 700 "$BACKUP_ROOT"
    
    BASE_INTERVAL=$(detect_base_interval)
    
    if [ "$action" = "prepare" ] || [ "$action" = "commit" ] || [ "$action" = "purge" ] || [ "$action" = "check-storage" ]; then
        check_dependencies
        check_rsync_capabilities
    fi

    case "$action" in
        prepare)
            agent_lock
            make_room_before_backup "$BASE_INTERVAL" >&2
            local full_path
            full_path=$(core_prepare_backup_target "$BASE_INTERVAL")
            echo "${full_path#$BACKUP_ROOT/}"
            ;;
        commit)
            agent_lock
            local t_0
            t_0=$(get_interval_path "$BASE_INTERVAL" 0)
            local t_used="$t_0"
            if [ -d "$t_0.tmp" ]; then t_used="$t_0.tmp"; fi
            core_commit_backup "$BASE_INTERVAL" "$t_used"
            ;;
        purge)
            agent_lock
            core_perform_all_promotions
            ;;
        status)
            print_snapshot_table "$BACKUP_ROOT"
            ;;
        check-job-done) 
            local ts
            ts=$(read_timestamp "$BACKUP_ROOT/$BASE_INTERVAL.0/$TIMESTAMP_FILE")
            if [ "$(is_backup_older_than_current_period "$BASE_INTERVAL" "$ts" "$START_TIME")" = "false" ]; then
                echo "true"
            else
                echo "false"
            fi 
            exit 0
            ;; 
        check-storage) 
            if touch "$BACKUP_ROOT/.w_test" 2>/dev/null; then
                rm "$BACKUP_ROOT/.w_test"
                echo "true"
            else
                echo "false"
                exit 0
            fi
            exit 0 
            ;;
    esac
}

## @brief Installs the agent script and wrapper.
do_install_agent() {
    local target_user="${1:-backup}"
    local wrapper_path="${WRAPPER_PATH:-/usr/local/bin/snapshot-wrapper.sh}"
    local install_path="${AGENT_INSTALL_PATH:-/usr/local/sbin/snapshot-agent.sh}"

    if [ "$(id -u)" -ne 0 ]; then die "Installation requires root."; fi
    
    # A new file moved into place, never written into the old one: a shell reads
    # its script piece by piece, so an agent action still running - a purge for
    # one of many clients - would otherwise go on in a mixture of two versions.
    if ! [ "$0" -ef "$install_path" ]; then
        cp -f "$0" "$install_path.new.$$" || die "Could not copy the agent."
        chmod 700 "$install_path.new.$$"
        chown 0:0 "$install_path.new.$$"
        mv -f "$install_path.new.$$" "$install_path" || die "Could not install the agent."
    fi
    chmod 700 "$install_path"
    chown 0:0 "$install_path"
    
    if ! id "$target_user" >/dev/null 2>&1; then
        useradd --system --home-dir /var/backups --no-create-home --shell /bin/false "$target_user"
    fi
    
    local rsync_bin sftp_bin s
    rsync_bin=$(command -v rsync 2>/dev/null || echo /usr/bin/rsync)
    sftp_bin=""
    for s in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/libexec/sftp-server /usr/lib/ssh/sftp-server /usr/lib/sftp-server; do
        [ -x "$s" ] && { sftp_bin="$s"; break; }
    done

    # The wrapper is the only thing between a client's key and root on this machine,
    # so it is written in plain POSIX sh and needs nothing but a shell, logger (optional)
    # and readlink -f - all present in coreutils and in busybox.
    {
        echo "#!/bin/sh"
        echo "# snapshot-wrapper.sh - forced command for backup client keys."
        echo "# Generated by snapshot-backup.sh $SCRIPT_VERSION (--install). Edit ENFORCE only."
        echo "AGENT=\"$install_path\""
        echo "STORAGE_ROOT=\"$BASE_STORAGE_PATH\""
        echo "RSYNC=\"$rsync_bin\""
        echo "SFTP_SERVER=\"$sftp_bin\""
        echo "ENFORCE=\"${WRAPPER_ENFORCE:-1}\""
        cat <<'WRAPPER'
#
# authorized_keys, one line per client (--setup-remote writes it):
#   command="/usr/local/bin/snapshot-wrapper.sh CLIENT",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...
#
# With CLIENT the key is confined to that client:
#   - agent actions only with --client CLIENT; no install, no --config (the agent would
#     source that file as shell code)
#   - rsync only as a server, only below STORAGE_ROOT/CLIENT (checked after resolving
#     symlinks), only with known options; no protect-args, which would hide the paths
#   - no sftp. sftp-server cannot be confined: "-R -d" means read-only and a start
#     directory, not a jail, so it reads the whole server as root - other clients'
#     backups included. A key that needs --mount gets it explicitly and knowingly:
#       command="/usr/local/bin/snapshot-wrapper.sh CLIENT --allow-mount",...
# Without CLIENT (an old line) it behaves as before 18.7 and logs "unpinned".
# ENFORCE=0 logs what it would refuse and lets it through - for moving existing clients over.
export LC_ALL=C
CLIENT="${1:-}"
MOUNT="${2:-}"
CMD="${SSH_ORIGINAL_COMMAND:-}"
REASON=""

note() { command -v logger >/dev/null 2>&1 && logger -t snapshot-wrapper -- "$*"; return 0; }
refuse() { REASON="$1"; return 1; }

# a path may be used only inside this client's own tree - also after symlinks are resolved
inside_own_tree() {
    p="$1"; base="$STORAGE_ROOT/$CLIENT"
    case "$p" in *..*) refuse "path with ..: $p"; return 1 ;; esac
    case "$p" in "$base"|"$base"/*) ;; *) refuse "path outside $base: $p"; return 1 ;; esac
    q="$p"
    while [ ! -e "$q" ] && [ "$q" != "$base" ] && [ "$q" != "/" ]; do q=$(dirname "$q"); done
    r=$(readlink -f "$q" 2>/dev/null) || { refuse "cannot resolve $q"; return 1; }
    rb=$(readlink -f "$base" 2>/dev/null) || rb="$base"
    case "$r" in "$rb"|"$rb"/*) return 0 ;; esac
    refuse "path leaves $base through a link: $p -> $r"
}

check_agent() {
    shift
    action=""; client_ok=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --agent-mode) shift ;;
            --action) [ $# -ge 2 ] || { refuse "--action without value"; return 1; }; action="$2"; shift 2 ;;
            --client) { [ $# -ge 2 ] && [ "$2" = "$CLIENT" ]; } || { refuse "--client ${2:-} is not $CLIENT"; return 1; }; client_ok=1; shift 2 ;;
            --retain-hourly|--retain-daily|--retain-weekly|--retain-monthly|--retain-yearly|--smart-purge-limit|--smart-purge-slots)
                [ $# -ge 2 ] || { refuse "$1 without value"; return 1; }
                case "$2" in ''|*[!0-9]*) refuse "$1 $2 is not a number"; return 1 ;; esac
                shift 2 ;;
            *) refuse "agent argument not allowed: $1"; return 1 ;;
        esac
    done
    case "$action" in
        version) return 0 ;;
        prepare|commit|purge|status|check-storage|check-job-done) [ -n "$client_ok" ] || { refuse "$action without --client"; return 1; } ;;
        *) refuse "agent action not allowed: $action"; return 1 ;;
    esac
}

check_rsync() {
    shift
    [ "${1:-}" = "--server" ] || { refuse "rsync not in server mode"; return 1; }
    shift
    dot=0; paths=0
    for a in "$@"; do
        if [ "$dot" = 1 ]; then inside_own_tree "$a" || return 1; paths=$((paths + 1)); continue; fi
        case "$a" in
            .) dot=1 ;;
            --sender) ;;
            --*)
                case "$a" in
                    --delete|--delete-before|--delete-during|--delete-delay|--delete-after|--delete-excluded|\
                    --numeric-ids|--inplace|--partial|--ignore-errors|--force|--safe-links|--munge-links|\
                    --fake-super|--existing|--ignore-existing|--size-only|--no-*|--fsync|--stats) ;;
                    --timeout=*|--contimeout=*|--bwlimit=*|--max-delete=*|--max-size=*|--min-size=*|\
                    --modify-window=*|--compress-level=*|--compress-choice=*|--checksum-choice=*|\
                    --info=*|--debug=*|--log-format=*|--out-format=*|--iconv=*) ;;
                    --link-dest=*|--compare-dest=*|--copy-dest=*) inside_own_tree "${a#*=}" || return 1 ;;
                    --partial-dir=*) case "${a#*=}" in /*|*..*) refuse "partial-dir must be relative: $a"; return 1 ;; esac ;;
                    *) refuse "rsync option not allowed: $a"; return 1 ;;
                esac ;;
            -*)
                # "-vlogDtprRze.iLsfxCIvu": the letters before "e." are options, after it the
                # protocol's capability flags. Refused among the options: s (protect-args hides
                # the paths from this check), K/L/k (follow symlinks out of the tree), b (backups
                # elsewhere), and anything unknown.
                opts="${a#-}"; opts="${opts%%e.*}"
                case "$opts" in *[!vlogDtprRzxHAXcSWuniIOJUNdqPhECmyF]*) refuse "rsync short option not allowed in $a"; return 1 ;; esac ;;
            *) refuse "unexpected rsync argument: $a"; return 1 ;;
        esac
    done
    [ "$dot" = 1 ] && [ "$paths" -ge 1 ] || { refuse "rsync without a path"; return 1; }
}

decide() {
    [ -n "$CMD" ] || { refuse "interactive login"; return 1; }
    set -f
    # shellcheck disable=SC2086
    set -- $CMD
    case "$1" in
        snapshot-agent.sh|*/snapshot-agent.sh) check_agent "$@" ;;
        rsync|*/rsync) check_rsync "$@" ;;
        internal-sftp|sftp-server|*/sftp-server)
            [ "$MOUNT" = "--allow-mount" ] || { refuse "sftp not enabled for this key (it cannot be confined; --allow-mount)"; return 1; }
            [ -n "$SFTP_SERVER" ] || refuse "no sftp-server on this machine" ;;
        *) refuse "command not allowed: $1" ;;
    esac
}

# before 18.7, and still for authorized_keys lines without a client name
legacy() {
    set -f
    # shellcheck disable=SC2086
    case "$CMD" in
        *snapshot-agent.sh*|*--action*) exec "$AGENT" $CMD ;;
        *sftp-server*|internal-sftp) exec "${SFTP_SERVER:-/usr/lib/openssh/sftp-server}" ;;
        rsync*) exec $CMD ;;
        *) echo "Access Denied."; exit 1 ;;
    esac
}

if [ -z "$CLIENT" ]; then
    note "unpinned key (no client name in authorized_keys) - legacy mode: $CMD"
    legacy
fi
case "$CLIENT" in *[!A-Za-z0-9._-]*|*..*|.*) note "DENY invalid client name '$CLIENT'"; echo "Access Denied."; exit 1 ;; esac
case "$MOUNT" in ''|--allow-mount) ;; *) note "DENY client=$CLIENT unknown wrapper option '$MOUNT'"; echo "Access Denied."; exit 1 ;; esac

if decide; then
    set -f
    # shellcheck disable=SC2086
    set -- $CMD
    case "$1" in
        *snapshot-agent.sh) shift; exec "$AGENT" "$@" ;;
        *rsync) shift; exec "$RSYNC" "$@" ;;
        *) exec "$SFTP_SERVER" -R -d "$STORAGE_ROOT/$CLIENT" ;;
    esac
fi
note "DENY client=$CLIENT reason=$REASON cmd=$CMD"
if [ "$ENFORCE" = 0 ]; then
    note "AUDIT client=$CLIENT: ENFORCE=0, letting it through the old way"
    legacy
fi
echo "Access Denied: $REASON" >&2
exit 1
WRAPPER
    } > "$wrapper_path.new"
    chmod 755 "$wrapper_path.new"
    mv -f "$wrapper_path.new" "$wrapper_path"
    log "INFO" "Agent installed. Wrapper: $wrapper_path (ENFORCE=${WRAPPER_ENFORCE:-1})"
}

## @brief Confines one key in authorized_keys to the wrapper for one client.
##
## Runs on the backup server as the login user, over the key that is being locked -
## so it works only while that key is still unrestricted, i.e. during --setup-remote.
## $1 = client name, $2 = the key's base64 blob (second field of the .pub file).
do_lock_key() {
    local client="$1" blob="$2"
    local f="${HOME:-/root}/.ssh/authorized_keys"
    local wrapper="${WRAPPER_PATH:-/usr/local/bin/snapshot-wrapper.sh}"
    local opts="command=\"$wrapper $client\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
    validate_client_name "$client"
    case "$blob" in ''|*[!A-Za-z0-9+/=]*) die "lock-key: invalid key blob." ;; esac
    [ -f "$f" ] || die "lock-key: $f not found."
    grep -q "$blob" "$f" || die "lock-key: key not found in $f."
    cp -p "$f" "$f.before-lock-$(date +%s)"
    # Whatever options the line had are replaced; key type, blob and comment stay.
    awk -v b="$blob" -v o="$opts" '
        {
            n = split($0, w, " ")
            for (i = 2; i <= n; i++) if (w[i] == b && w[i-1] ~ /^(ssh-|ecdsa-|sk-)/) {
                line = w[i-1]; for (j = i; j <= n; j++) line = line " " w[j]
                print o " " line; next
            }
            print
        }' "$f" > "$f.tmp.$$" || die "lock-key: rewrite failed."
    chmod 600 "$f.tmp.$$"
    mv -f "$f.tmp.$$" "$f"
    log "INFO" "Key locked to $wrapper $client."
}

# ==============================================================================
# 6. CONFIG & SETUP
# ==============================================================================

## @brief Collects transfer statistics for reporting.
collect_stats() {
    local logfile="$1"
    local stats_history="/var/log/snapshot-backup-stats.csv"
    if [ ! -f "$logfile" ]; then return; fi
    
    local size_line
    size_line=$(grep -E "Total (transferred )?file size" "$logfile" | tail -n 1)
    
    if [ -n "$size_line" ]; then
        local raw_bytes
        raw_bytes=$(echo "$size_line" | awk -F': ' '{print $2}' | sed 's/[^0-9]//g')
        local timestamp
        timestamp=$(date +%s)
        
        if [ -n "$raw_bytes" ] && echo "$raw_bytes" | grep -qE "^[0-9]+$"; then
            echo "$timestamp,$raw_bytes" >> "$stats_history"
        fi
    fi
}

## @brief Loads and sanitizes configuration from file.
load_config() {
    local config_file="$1"
    
    if [ -f "$config_file" ]; then
        local file_ver
        file_ver=$(grep "^CONFIG_VERSION=" "$config_file" | head -n 1 | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        if [ -z "$file_ver" ] || [ "$file_ver" != "$EXPECTED_CONFIG_VERSION" ]; then
            die "Config Version Mismatch in $config_file."
        fi
        # LOCK_DIR is derived from PIDFILE when the script loads, which happens
        # before this file is read. A config that sets only PIDFILE would
        # therefore keep the default lock: two instances on one host would
        # report separate PIDs while sharing one lock, and the second would
        # refuse to start for no visible reason. Clearing it first lets a
        # config set it explicitly and otherwise re-derives it from the
        # PIDFILE the config actually chose.
        LOCK_DIR=""
        . "$config_file"
        [ -z "${LOCK_DIR:-}" ] && LOCK_DIR="${PIDFILE%.pid}.lock"
    fi
    
    if [ -n "${LOCK_DIR:-}" ]; then AGENT_LOCK_DIR="$LOCK_DIR"; fi
    
    BACKUP_ROOT="${BACKUP_ROOT:-$DEFAULT_BACKUP_ROOT}"
    BACKUP_MODE="${BACKUP_MODE:-LOCAL}"
    CLIENT_NAME="${CLIENT_NAME:-$(hostname)}"
    REMOTE_PORT="${REMOTE_PORT:-22}"
    BASE_STORAGE_PATH="${BASE_STORAGE:-$BASE_STORAGE_PATH}"
    BASE_INTERVAL=$(detect_base_interval)
}

## @brief Acquires an exclusive lock to prevent concurrent runs.
acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$PIDFILE"
        HAS_LOCK=true
        return 0
    fi
    
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log "ERROR" "Instance already running (PID: $pid)."
        notify "Snapshot Backup" "Backup locked by PID $pid." "critical"
        exit 2
    fi
    
    sleep 0.1
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$PIDFILE"
        HAS_LOCK=true
        return 0
    fi
    
    rmdir "$LOCK_DIR" 2>/dev/null
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$PIDFILE"
        HAS_LOCK=true
        return 0
    else
        die "Could not acquire lock."
    fi
}

## @brief Generic cleanup on exit.
## @brief Runs a configured hook command and reports whether it succeeded.
##
## Hooks are called, not listened to: the script waits and reads the exit code.
## That is the point - a PRE hook that fails must be able to stop the backup,
## because a snapshot that was not created is not a snapshot the backup may
## quietly do without.
##
## $1 = name for the log, $2 = command line, $3.. = arguments passed to it.
## Returns the command's exit code, or 0 when nothing is configured.
##
## A hook whose failure should not matter says so in ordinary shell:
##   PRE_RUN_CMD="/usr/local/sbin/something || true"
run_hook() {
    local name="$1"
    local cmd="$2"
    shift 2

    [ -z "$cmd" ] && return 0

    log "INFO" "Hook $name: $cmd"
    # The config carries a command line, not a path, so it goes through sh -c:
    # arguments and shell constructs in it have to survive.
    sh -c "$cmd" -- "$@"
    local rc=$?
    [ "$rc" -ne 0 ] && log "ERROR" "Hook $name failed with exit $rc"
    return $rc
}

cleanup() {
    if [ "$AGENT_MODE" = true ]; then
        agent_cleanup
        return
    fi

    local jobs
    jobs=$(jobs -p)
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

    # POST_RUN_CMD belongs here rather than at the end of the happy path: this
    # runs on success, on failure, on abort and on signal. Whatever a PRE hook
    # set up - an LVM snapshot, a frozen guest filesystem - then has exactly
    # one place that is guaranteed to tear it down, and a guest left frozen
    # because a backup died at 04:00 stays frozen until somebody notices.
    #
    # Only when a hook was actually armed: cleanup also runs on paths that
    # never started a backup, such as a refused lock.
    if [ "${_HOOKS_ARMED:-false}" = true ]; then
        _HOOKS_ARMED=false
        run_hook "POST_RUN_CMD" "${POST_RUN_CMD:-}" "${_RUN_EXIT_CODE:-0}" || true
    fi
}

# A signal ends the run. A trap on INT/TERM that only cleaned up let the shell
# carry on afterwards (dash, busybox and bash alike): the lock was gone and
# POST_RUN_CMD had run mid-run, and the run went on to commit and exit 0.
# exit hands over to the EXIT trap, which cleans up once.
trap cleanup EXIT
trap 'log "ERROR" "Stopped by SIGHUP."; exit 129' HUP
trap 'log "ERROR" "Stopped by SIGINT."; exit 130' INT
trap 'log "ERROR" "Stopped by SIGTERM."; exit 143' TERM

## @brief Prints the PIDs of all processes below $1, deepest first (reads /proc).
_descendants() {
    local parent="$1" d p pp
    for d in /proc/[0-9]*; do
        p="${d#/proc/}"
        pp=$(sed -n 's/.*) [A-Za-z] \([0-9]*\).*/\1/p' "$d/stat" 2>/dev/null)
        if [ "$pp" = "$parent" ]; then
            _descendants "$p"
            echo "$p"
        fi
    done
}

## @brief Stops the run this config's PIDFILE names, and what it started.
## Before 18.7 this ran "pkill -f snapshot-backup.sh", which hit every process
## mentioning the script - runs of other configs, an editor, itself - while the
## rsync of the run it was meant for went on, and the run then committed.
kill_active_backups() {
    local pid
    pid=$(sanitize_int "$(cat "$PIDFILE" 2>/dev/null)")
    if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null; then
        log "WARN" "Stopping backup run $pid and the processes it started."
        # The run first, so it starts nothing new; its trap fires once the
        # command it waits for is gone, which is why rsync and ssh go as well.
        local tree
        tree=$(_descendants "$pid")
        kill "$pid" 2>/dev/null
        # shellcheck disable=SC2086
        [ -n "$tree" ] && kill $tree 2>/dev/null
        local i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done
        kill -0 "$pid" 2>/dev/null && die "Run $pid did not stop within 30 s."
    else
        log "INFO" "No backup running for this configuration."
    fi
    # A run that died without its cleanup leaves the lock behind.
    if [ -d "$LOCK_DIR" ] && ! kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        rm -f "$PIDFILE"
        rmdir "$LOCK_DIR" 2>/dev/null
    fi
    exit 0
}

# ==============================================================================
# 7. CLIENT UI & MAIN
# ==============================================================================

## @brief Prints the current configuration to stdout.
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

# Hooks
#
# Commands the script calls at points only it knows. They are called, not
# listened to: it waits and reads the exit code, so a PRE hook that fails stops
# the run. A hook whose failure should not matter says so in ordinary shell:
#   PRE_RUN_CMD="/usr/local/sbin/dump-databases.sh || true"
#
# PRE_RUN_CMD    after the lock is held, before anything else. For dumps.
# PRE_RSYNC_CMD  after the target is prepared, before the first file is read.
#                This is where an LVM snapshot or a filesystem freeze belongs:
#                the rotation before it can take minutes, and a snapshot held
#                open that long fills its copy-on-write area for nothing.
# POST_RUN_CMD   always, including on failure, abort and signal. Receives the
#                run's exit code as \$1. This is the only place guaranteed to
#                tear down what a PRE hook set up.
#                Use SINGLE quotes when the command refers to \$1:
#                  POST_RUN_CMD='/usr/local/sbin/thaw.sh \$1'
#                In double quotes the \$1 is expanded while this file is loaded,
#                and the hook receives the path of this file instead.
PRE_RUN_CMD="$PRE_RUN_CMD"
PRE_RSYNC_CMD="$PRE_RSYNC_CMD"
POST_RUN_CMD="$POST_RUN_CMD"

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

## @brief Helper to print configuration lists.
print_config_list() {
    local var_name="$1"
    eval "local val=\"\${$var_name:-}\""
    echo "$var_name='"
    [ -n "$val" ] && iterate_list "$val" _print_item
    echo "'"
}
## @brief Helper callback for printing items.
_print_item() { echo "    \"$1\""; }

## @brief Calculates human-readable time elapsed since a timestamp.
calc_time_ago() {
    local now="${2:-$(date +%s)}"
    local diff=$(( now - $1 ))
    if [ $diff -lt 60 ]; then
        echo "${diff}s ago"
    elif [ $diff -lt 3600 ]; then
        echo "$((diff/60))m ago"
    elif [ $diff -lt 86400 ]; then
        echo "$((diff/3600))h ago"
    else
        echo "$((diff/86400)) days ago"
    fi
}

## @brief Displays a table of existing snapshots.
print_snapshot_table() {
    local root_path="$1"
    printf "%-12s %-22s %-15s\n" "Snapshot" "Timestamp" "Age"
    local now_ts
    now_ts=$(date +%s)
    
    for i in $INTERVALS; do
        ls -d "$root_path/$i."[0-9]* 2>/dev/null | sort -t. -k2,2n | while read snap_path; do
            local ts
            ts=$(read_timestamp "$snap_path/$TIMESTAMP_FILE")
            
            local date_str="UNKNOWN"
            local ago_str="-"
            if [ "$ts" != "0" ]; then
                date_str=$(ts_to_date "$ts" "+%Y-%m-%d %H:%M:%S")
                ago_str=$(calc_time_ago "$ts" "$now_ts")
            fi
            printf "%-12s %-22s %-15s\n" "$(basename "$snap_path")" "$date_str" "$ago_str"
        done
    done
}

## @brief Shows the current status of the backup system.
show_status() {
    echo "================================================================================"
    echo "                 SNAPSHOT BACKUP STATUS (v$SCRIPT_VERSION)"
    echo "================================================================================"
    local state="IDLE"
    [ -d "$LOCK_DIR" ] && state="RUNNING"
    printf "PROCESS:      ● %s\n" "$state"
    
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        printf "STORAGE:      ● REMOTE (%s@%s)\n" "$REMOTE_USER" "$REMOTE_HOST"
    else
        printf "STORAGE:      ● LOCAL\n"
        if [ -d "$BACKUP_ROOT" ]; then
             printf "FREE SPACE:   %s\n" "$(df -h "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
        fi
    fi

    local mount_state="NOT MOUNTED"
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then
        mount_state="MOUNTED"
    fi
    printf "MOUNT STATUS: %s\n" "$mount_state"

    local stats_history="/var/log/snapshot-backup-stats.csv"
    if [ -f "$stats_history" ]; then
        local avg_bytes
        avg_bytes=$(tail -n 10 "$stats_history" | awk -F',' '{sum+=$2; count++} END {if (count>0) print sum/count}')
        if [ -n "$avg_bytes" ] && [ "$(echo "$avg_bytes > 0" | awk '{print ($1 > 0)}')" -eq 1 ]; then
             local avg_mb
             avg_mb=$(echo "$avg_bytes" | awk '{printf "%.2f", $1/1024/1024}')
             printf "AVG NEW DATA: ~%s MB (Last 10 runs)\n" "$avg_mb"
        fi
    fi
    
    echo ""
    echo "LATEST SNAPSHOTS:"
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        echo "Fetching remote status from $REMOTE_HOST..."
        if ! run_remote_cmd "$REMOTE_AGENT --action status --client $CLIENT_NAME" 2>/dev/null; then
             echo "Error: Connection failed or Agent not found."
        fi
    else
        print_snapshot_table "$BACKUP_ROOT"
    fi
    exit 0
}

## @brief Checks if required dependencies are installed.
check_dependencies() {
    for cmd in rsync ssh; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Missing dependency: $cmd"
        fi
    done
}

## @brief Verifies if the local and remote agent versions match.
check_agent_version() {
    local v
    v=$(run_remote_cmd_with_timeout 5 "$REMOTE_AGENT --agent-mode --action version")
    if [ "$v" != "$SCRIPT_VERSION" ]; then
        log "WARN" "Agent version mismatch (Local: $SCRIPT_VERSION, Remote: $v)."
    fi
}

## @brief Tests connectivity to the remote server.
test_remote_connection() {
    run_remote_cmd_with_timeout "$NETWORK_TIMEOUT" "$REMOTE_AGENT --agent-mode --action version" >/dev/null 2>&1
}

## @brief Deploys the script as an agent to a remote host.
do_deploy_agent() {
    local target="$1"
    [ -z "$target" ] && target="$REMOTE_USER@$REMOTE_HOST"
    log "INFO" "Deploying Agent to $target..."
    scp -P $REMOTE_PORT -i "$REMOTE_KEY" "$0" "$target:/usr/local/sbin/snapshot-agent.sh"
    run_remote_cmd "/usr/local/sbin/snapshot-agent.sh --agent-mode --action install"
    log "SUCCESS" "Agent deployed."
}

## @brief Wizard for setting up remote SSH keys and deploying the agent.
do_setup_remote() {
    local target="$1"
    [ -z "$target" ] && target="$REMOTE_USER@$REMOTE_HOST"
    
    if [ ! -f "$REMOTE_KEY" ]; then
        mkdir -p "$(dirname "$REMOTE_KEY")"
        ssh-keygen -t ed25519 -f "$REMOTE_KEY" -N ""
    fi
    
    ssh-copy-id -i "$REMOTE_KEY.pub" "$target"
    do_deploy_agent "$target"

    # ssh-copy-id leaves the key unrestricted: root on the server for anyone who holds it.
    # Confine it to the wrapper for this client, over the same key, while it still works.
    local blob
    blob=$(awk '{print $2}' "$REMOTE_KEY.pub")
    if run_remote_cmd "/usr/local/sbin/snapshot-agent.sh --agent-mode --action lock-key --client $CLIENT_NAME --key-blob $blob"; then
        log "SUCCESS" "Key locked on the server: it can now only run backups for '$CLIENT_NAME'."
    else
        log "WARN" "Could not lock the key on the server. Add by hand, in front of the key in authorized_keys:"
        log "WARN" "  command=\"/usr/local/bin/snapshot-wrapper.sh $CLIENT_NAME\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
    fi
}

## @brief True when $1 is a newer version than $2.
##
## Compares dotted version numbers field by field. Needed because an upgrade
## that only checks for inequality will happily install an older file, and a
## CDN serving a stale copy is enough to make that happen - it did, and three
## machines were downgraded by one.
version_gt() {
    local a="$1" b="$2" i=1 fa fb
    [ "$a" = "$b" ] && return 1
    while [ "$i" -le 4 ]; do
        fa=$(sanitize_int "$(echo "$a" | cut -d. -f$i)")
        fb=$(sanitize_int "$(echo "$b" | cut -d. -f$i)")
        [ "$fa" -gt "$fb" ] && return 0
        [ "$fa" -lt "$fb" ] && return 1
        i=$((i+1))
    done
    return 1
}

## @brief Fetches the published script and replaces this one with it.
##
## What this does NOT do is verify authorship. HTTPS establishes that the file
## came from the host in the URL and was not altered on the way; it says
## nothing about who put it there. There is no signature to check, so a
## compromised repository would be installed like any other update. That is the
## honest limit of a self-updater without signing, and the reason this never
## runs on its own - it is a command somebody types.
##
## $1 = "check" to report only.
do_upgrade() {
    local mode="${1:-install}"
    local url="${UPGRADE_URL:-https://raw.githubusercontent.com/schnebeck/snapshot-backup/main/snapshot-backup.sh}"
    local target="$0"

    [ "$(id -u)" -eq 0 ] || die "Upgrade requires root."

    # Not while a backup is running: replacing the file underneath a running
    # shell is how you get a script that reads half of one version and half of
    # another.
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        die "A backup is running (PID $(cat "$PIDFILE")). Not upgrading."
    fi

    command -v curl >/dev/null 2>&1 || die "curl is required for --upgrade."

    local tmp
    tmp=$(mktemp) || die "Could not create a temporary file."

    log "INFO" "Fetching $url"
    # The no-cache header asks intermediaries for the current file. It is not a
    # guarantee - a CDN may serve a stale copy anyway, which is why the version
    # check below is the actual protection rather than a formality.
    if ! curl -fsSL --proto "=https" --tlsv1.2 --max-time 60 \
              -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
              -o "$tmp" "$url"; then
        rm -f "$tmp"
        die "Download failed."
    fi

    # Three checks before anything is replaced. Each one has a failure mode it
    # is there for: a captive portal returning HTML, a truncated transfer, a
    # file that is not this program.
    local new_ver
    new_ver=$(grep -m1 '^SCRIPT_VERSION=' "$tmp" | cut -d'"' -f2)
    if [ -z "$new_ver" ]; then
        rm -f "$tmp"
        die "Downloaded file carries no SCRIPT_VERSION - this is not the script."
    fi
    if ! sh -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        die "Downloaded file is not valid shell - refusing to install it."
    fi
    if ! grep -q "^core_backup_execution()" "$tmp"; then
        rm -f "$tmp"
        die "Downloaded file does not look like this program - refusing."
    fi

    printf 'Installed: %s\nAvailable: %s\n' "$SCRIPT_VERSION" "$new_ver"

    if [ "$new_ver" = "$SCRIPT_VERSION" ]; then
        log "INFO" "Already at $SCRIPT_VERSION."
        rm -f "$tmp"
        return 0
    fi

    # An upgrade does not go backwards. Without this, a stale copy from a cache
    # is installed as eagerly as a new release.
    if ! version_gt "$new_ver" "$SCRIPT_VERSION" && [ "$mode" != "force" ]; then
        rm -f "$tmp"
        log "WARN" "Published version $new_ver is older than the installed $SCRIPT_VERSION - not installing."
        log "WARN" "A CDN may be serving a stale copy; try again later, or --upgrade --force to install it anyway."
        return 0
    fi

    if [ "$mode" = "check" ]; then
        rm -f "$tmp"
        return 0
    fi

    local backup="${target}.${SCRIPT_VERSION}"
    cp -p "$target" "$backup" || { rm -f "$tmp"; die "Could not back up $target."; }
    cat "$tmp" > "$target" || { rm -f "$tmp"; die "Could not write $target."; }
    chmod 700 "$target"
    rm -f "$tmp"

    log "SUCCESS" "Upgraded $SCRIPT_VERSION -> $new_ver (previous kept as $backup)"
    printf 'The agent on the backup server is a copy of this file and is not\n'
    printf 'updated by this: run --deploy-agent to bring it along.\n'
}

## @brief Mounts the backup storage (Local bind or Remote SSHFS).
do_mount() {
    local mountpoint="$1"
    local client="${2:-$CLIENT_NAME}"
    
    [ -z "$mountpoint" ] && mountpoint="$BACKUP_ROOT"
    [ ! -d "$mountpoint" ] && mkdir -p "$mountpoint"
    
    if mountpoint -q "$mountpoint"; then
        log "WARN" "Already mounted."
        return
    fi
    
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        command -v sshfs >/dev/null || die "sshfs required."
        sshfs -p "$REMOTE_PORT" -o "IdentityFile=$REMOTE_KEY" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_STORAGE_ROOT/$client" "$mountpoint"
    else
        mount --bind "$BACKUP_ROOT" "$mountpoint"
    fi
    log "SUCCESS" "Mounted to $mountpoint"
}

## @brief Unmounts the backup storage.
do_umount() {
    local mp="$1"
    [ -z "$mp" ] && mp="$BACKUP_ROOT"
    umount "$mp" && log "SUCCESS" "Unmounted $mp"
}

## @brief CLI Check: Is a backup currently running?
check_is_running_cli() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "true"
    else
        echo "false"
        exit 1
    fi
    exit 0
}

## @brief CLI Check: Is the backup for the current interval done?
check_is_job_done_cli() {
    # 1. REMOTE MODE: Delegate the check to the remote agent
    if [ "$BACKUP_MODE" = "REMOTE" ]; then
        local res
        # Query the agent using the configured timeout to prevent hanging on network issues.
        # We filter the output (tail/tr) to strip potential SSH banners or MOTD noise.
        res=$(run_remote_cmd_with_timeout "$NETWORK_TIMEOUT" "$REMOTE_AGENT --action check-job-done --client $CLIENT_NAME" 2>/dev/null | tail -n 1 | tr -d '[:space:]')

        if [ "$res" = "true" ]; then
            echo "true"
            exit 0
        else
            echo "false"
            exit 1
        fi
    fi

    # 2. LOCAL MODE: Check the local filesystem directly
    if [ ! -d "$BACKUP_ROOT/$BASE_INTERVAL.0" ]; then
        echo "false"
        exit 1
    fi
    
    # Verify if the existing snapshot covers the current period (In-Place Logic)
    local ts
    ts=$(read_timestamp "$BACKUP_ROOT/$BASE_INTERVAL.0/$TIMESTAMP_FILE")
    if [ "$(is_backup_older_than_current_period "$BASE_INTERVAL" "$ts" "$START_TIME")" = "false" ]; then
        echo "true"
    else
        echo "false"
    fi
    exit 0
}

## @brief CLI Check: Is the storage writable?
check_has_storage_cli() {
    if [ "$BACKUP_MODE" = "LOCAL" ]; then
        if touch "$BACKUP_ROOT/.w_test" 2>/dev/null; then
            rm "$BACKUP_ROOT/.w_test"
            echo "true"
        else
            echo "false"
            exit 1
        fi
    else 
        if run_remote_cmd "$REMOTE_AGENT --action check-storage --client $CLIENT_NAME" 2>/dev/null; then
            :
        else
            echo "false"
            exit 1
        fi
    fi
    exit 0
}

## @brief Displays the help message.
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]
Options:
  --version, -v          Print version.
  --show-config          Print configuration.
  --status               Show status report.
  --verify               Force Deep-Checksum Verification.
  --kill, -k             Stop running backups.
  --mount [PATH]         Mount backup storage.
  --umount [PATH]        Unmount backup storage.
  --deploy-agent [TG]    Deploy agent to target (user@host).
  --setup-remote [TG]    Wizard: SSH Setup & Deployment.
  --upgrade [--check|--force]
                         Fetch the published version and install it. Never
                         downgrades unless --force is given.
  --is-running           Check if backup is running (exit code 0/1).
  --is-job-done          Check if today's backup is done (exit code 0/1).
  --has-storage          Check if storage is writable (exit code 0/1).
  --install [USER]       Install agent wrapper (Root required).
  --config, -c [FILE]    Load custom config file.
  --timeout [SEC]        Set custom timeout (for checks).
  --help, -h             Show this help message.
EOF
    exit 0
}

## @brief Main entry point for Client mode operations.
client_main() {
    load_config "$CONFIG_FILE"

    local action="BACKUP"
    local action_target=""
    local cli_timeout=""
    local cli_force_verify=false

    while [ $# -gt 0 ]; do
        case $1 in
            --help|-h) show_help ;; 
            --version|-v) echo "$SCRIPT_VERSION"; exit 0 ;;
            --status) action="STATUS" ;; 
            --mount) 
                action="MOUNT"
                if [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then action_target="$2"; shift; fi
                ;;
            --umount) 
                action="UMOUNT"
                if [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then action_target="$2"; shift; fi
                ;;
            --kill|-k) action="KILL" ;;
            --deploy-agent) action="DEPLOY"; if [ -n "${2:-}" ]; then action_target="$2"; shift; fi ;;
            --setup-remote) action="SETUP_REMOTE"; if [ -n "${2:-}" ]; then action_target="$2"; shift; fi ;;
            --upgrade) action="UPGRADE"
                       case "${2:-}" in
                           --check) action_target="check"; shift ;;
                           --force) action_target="force"; shift ;;
                       esac ;;
            --install) action="INSTALL"; if [ -n "${2:-}" ]; then action_target="$2"; shift; fi ;;
            --is-running) action="IS_RUNNING" ;;
            --is-job-done) action="IS_JOB_DONE" ;;
            --has-storage) action="HAS_STORAGE" ;;
            --show-config) action="SHOW_CONFIG" ;;
            
            # Configuration Overrides
            --verify) cli_force_verify="true" ;; 
            --timeout) cli_timeout=$(sanitize_int "$2"); shift ;;
            --config|-c) load_config "$2"; shift ;;
            --debug) DEBUG_MODE="true" ;;            
            *) 
                echo "Error: Unknown option '$1'" >&2
                show_help
                exit 1 
                ;;
        esac
        shift
    done

    # Apply Sticky CLI Overrides
    if [ -n "$cli_timeout" ]; then NETWORK_TIMEOUT="$cli_timeout"; fi
    if [ "$cli_force_verify" = "true" ]; then FORCE_VERIFY=true; fi

    case "$action" in
        SHOW_CONFIG) show_config ;;
        STATUS)      show_status ;;
        MOUNT)       do_mount "$action_target"; exit 0 ;;
        UMOUNT)      do_umount "$action_target"; exit 0 ;;
        KILL)        kill_active_backups ;;
        DEPLOY)      do_deploy_agent "$action_target"; exit 0 ;;
        SETUP_REMOTE) do_setup_remote "$action_target"; exit 0 ;;
        UPGRADE)     do_upgrade "${action_target:-install}"; exit 0 ;;
        INSTALL)     do_install_agent "$action_target"; exit 0 ;;
        IS_RUNNING)  check_is_running_cli ;;
        IS_JOB_DONE) check_is_job_done_cli ;;
        HAS_STORAGE) check_has_storage_cli ;;
        BACKUP)
            check_dependencies
            check_rsync_capabilities
            acquire_lock
            log_startup_summary

            # From here on a POST_RUN_CMD is owed, whatever happens.
            _HOOKS_ARMED=true
            _RUN_EXIT_CODE=1
            if ! run_hook "PRE_RUN_CMD" "${PRE_RUN_CMD:-}"; then
                die "PRE_RUN_CMD failed - not backing up."
            fi

            for i in $INTERVALS; do
                consolidate_directory_indices "$i"
            done
            
            if [ "${DEEP_VERIFY_INTERVAL_DAYS:-0}" -gt 0 ] && [ "$FORCE_VERIFY" = false ]; then
                 local last_v
                 last_v=$(cat "$LAST_VERIFY_FILE" 2>/dev/null || echo 0)
                 [ $(( (START_TIME - last_v) / 86400 )) -ge "$DEEP_VERIFY_INTERVAL_DAYS" ] && FORCE_VERIFY=true
            fi
            
            [ "$FORCE_VERIFY" = true ] && RSYNC_EXTRA_OPTS="${RSYNC_EXTRA_OPTS:-} --checksum"
            
            if [ "$BACKUP_MODE" = "REMOTE" ]; then
                _perform_remote_backup_logic
            else 
                _perform_local_backup_logic "$BASE_INTERVAL"
            fi
            
            _RUN_EXIT_CODE=0
            rmdir "$LOCK_DIR" 2>/dev/null
            rm -f "$PIDFILE"
            collect_stats "$LOGFILE"
            ;;
    esac
}

## @brief Script entry point.
main() {
    START_TIME=$(date +%s)
    case "${1:-}" in --agent-mode) AGENT_MODE=true ;; esac
    [ "$(basename "$0")" = "snapshot-agent.sh" ] && AGENT_MODE=true
    
    if [ "$AGENT_MODE" = true ]; then
        agent_main "$@"
    else
        client_main "$@"
    fi
}

main "$@"