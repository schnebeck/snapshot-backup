#!/bin/sh

# ==============================================================================
## @file    snapshot-backup.sh
## @brief   Unified Snapshot Backup Client & Agent (POSIX sh)
## @version 18.2
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

SCRIPT_VERSION="18.2"
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

## @brief Sends a system notification if enabled.
notify() {
    local title="$1"
    local msg="$2"
    local urgency="${3:-normal}"
    
    if [ "$ENABLE_NOTIFICATIONS" != true ]; then return 0; fi
    
    (
        set +e
        if ! command -v notify-send >/dev/null 2>&1; then exit 0; fi
        
        local user_id
        user_id=$(id -u)
        
        if [ "$user_id" -eq 0 ]; then
             local target_user="${SUDO_USER:-}"
             if [ -z "$target_user" ]; then
                 target_user=$(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | head -n1)
             fi
             
             if [ -n "$target_user" ] && id "$target_user" >/dev/null 2>&1; then
                 local target_uid
                 target_uid=$(id -u "$target_user")
                 export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$target_uid/bus"
                 compat_run_with_timeout 5 sudo -E -u "$target_user" notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
             fi
        else
             compat_run_with_timeout 5 notify-send -u "$urgency" -a "Snapshot Backup" "$title" "$msg" 2>/dev/null
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

    local week_fmt="%V"
    if ! date +%V >/dev/null 2>&1; then week_fmt="%W"; fi
    
    case "$interval" in
        hourly)  ts_to_date "$ts" "+%Y%m${week_fmt}%d%H" ;;
        daily)   ts_to_date "$ts" "+%Y%m${week_fmt}%d" ;;
        weekly)  ts_to_date "$ts" "+%Y%m${week_fmt}" ;;
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
    local status_file="/tmp/snapshot_rsync_status.$$"
    
    ("$@" --timeout=300 $RSYNC_PROGRESS_OPTS 2>&1; echo $? > "$status_file") | while IFS= read -r line; do
            if echo "$line" | grep -q "[0-9]%[ ]"; then
                local now
                now=$(date +%s)
                if [ $((now - last_log_time)) -ge "$log_interval" ]; then
                     [ "${ENABLE_NOTIFICATIONS:-false}" = true ] && notify "Snapshot Backup" "Progress: $(echo "$line" | grep -o "[0-9]*%" | head -1)" "low"
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
    fi
    
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
    
    create_exclude_list
    
    _exec_item() {
        local src="$1"
        [ ! -e "$src" ] && return
        
        if [ "$_CTX_MODE" = "REMOTE" ]; then
             if ! run_with_retry rsync $_CTX_RSYNC_OPTS -e "$_CTX_SSH_CMD_OPTS" --exclude-from="$TEMP_EXCLUDE_FILE" -R "$src" "$_CTX_DEST_BASE/"; then
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
    
    local target_path
    target_path=$(core_prepare_backup_target "$int")
    
    local r_opts="-aH $RSYNC_ACL_OPT $RSYNC_XATTR_OPT --delete --numeric-ids -x --stats"
    [ -n "${RSYNC_EXTRA_OPTS:-}" ] && r_opts="$r_opts $RSYNC_EXTRA_OPTS"
    
    local v_status=0
    if ! core_backup_execution "LOCAL" "$target_path" "$r_opts" "" ""; then
        v_status=1
    fi
    
    if [ "$v_status" -eq 0 ]; then
        [ "$FORCE_VERIFY" = true ] && { mkdir -p "$(dirname "$LAST_VERIFY_FILE")"; date +%s > "$LAST_VERIFY_FILE"; }
        core_commit_backup "$int" "$target_path"
        core_perform_all_promotions
        log "INFO" "Backup Summary: Success."
    else
        log "ERROR" "Backup failed. Cleaning up temp files."
        [ "${target_path%.tmp}" != "$target_path" ] && safe_rm "$target_path"
    fi
}

## @brief Orchestrates the remote backup process via agent.
_perform_remote_backup_logic() {
    if ! test_remote_connection; then die "Server unreachable."; fi
    check_agent_version
    
    local c_opts
    c_opts="$(get_retention_args)"
    
    local target_suffix
    target_suffix=$(run_remote_cmd "$REMOTE_AGENT --action prepare --client $CLIENT_NAME $c_opts") || die "Remote preparation failed."
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
    
    run_remote_cmd "$REMOTE_AGENT --action commit --client $CLIENT_NAME $c_opts" || exit 1
    
    local p_opts=""
    [ "$SPACE_LOW_LIMIT_GB" -gt 0 ] && p_opts="--smart-purge-limit $SPACE_LOW_LIMIT_GB"
    run_remote_cmd "$REMOTE_AGENT --action purge --client $CLIENT_NAME $c_opts $p_opts" || exit 1
    
    log "INFO" "Backup Summary: Success."
}

## @brief Helper to generate retention arguments for agent calls.
get_retention_args() {
    echo "--retain-hourly $RETAIN_HOURLY --retain-daily $RETAIN_DAILY --retain-weekly $RETAIN_WEEKLY --retain-monthly $RETAIN_MONTHLY --retain-yearly $RETAIN_YEARLY"
}

# ==============================================================================
# 5. AGENT INTERFACE
# ==============================================================================

## @brief Removes agent lock file on exit.
agent_cleanup() {
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
            --config|-c) load_config "$2"; shift 2 ;;
            --agent-mode) shift ;;
            --version) echo "$SCRIPT_VERSION"; exit 0 ;;
            *) shift ;;
        esac
    done
    
    case "$action" in
        version) echo "$SCRIPT_VERSION"; exit 0 ;;
        install) do_install_agent; exit 0 ;;
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
            mkdir -p "$AGENT_LOCK_DIR"
            echo $$ > "$AGENT_LOCK_DIR/$CLIENT_NAME.lock"
            HAS_LOCK=true
            local full_path
            full_path=$(core_prepare_backup_target "$BASE_INTERVAL")
            echo "${full_path#$BACKUP_ROOT/}"
            ;;
        commit)
            local t_0
            t_0=$(get_interval_path "$BASE_INTERVAL" 0)
            local t_used="$t_0"
            if [ -d "$t_0.tmp" ]; then t_used="$t_0.tmp"; fi
            core_commit_backup "$BASE_INTERVAL" "$t_used"
            ;;
        purge)
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
    local install_path="/usr/local/sbin/snapshot-agent.sh"
    
    if [ "$(id -u)" -ne 0 ]; then die "Installation requires root."; fi
    
    if ! [ "$0" -ef "$install_path" ]; then cp -f "$0" "$install_path"; fi
    chmod 700 "$install_path"
    chown 0:0 "$install_path"
    
    if ! id "$target_user" >/dev/null 2>&1; then
        useradd --system --home-dir /var/backups --no-create-home --shell /bin/false "$target_user"
    fi
    
    cat > "$wrapper_path" <<EOF
#!/bin/bash
export LC_ALL=C
CMD="\${SSH_ORIGINAL_COMMAND:-\$*}"
case "\$CMD" in
    *snapshot-agent.sh*|*--action*) exec $install_path \$CMD ;;
    *sftp-server*) exec /usr/lib/openssh/sftp-server ;;
    rsync*) exec \$CMD ;;
    *) echo "Access Denied."; exit 1 ;;
esac
EOF
    chmod +x "$wrapper_path"
    log "INFO" "Agent installed."
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
        . "$config_file"
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
}

trap cleanup EXIT INT TERM

## @brief Kills active backup processes if requested.
kill_active_backups() {
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log "WARN" "Killing process $pid..."
            kill "$pid"
        fi
        rm -f "$PIDFILE" "$LOCK_DIR"
    fi
    pkill -f "$(basename "$0")" 2>/dev/null || true
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
        INSTALL)     do_install_agent "$action_target"; exit 0 ;;
        IS_RUNNING)  check_is_running_cli ;;
        IS_JOB_DONE) check_is_job_done_cli ;;
        HAS_STORAGE) check_has_storage_cli ;;
        BACKUP)
            check_dependencies
            check_rsync_capabilities
            acquire_lock
            log_startup_summary

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