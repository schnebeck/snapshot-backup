#!/bin/bash

# ==============================================================================
## @file    snapshot-backup.sh
## @brief   Intelligent snapshot rotation script using rsync and hardlinks.
## @details Implements a "Dynamic Waterfall Rotation" policy with precise
##          delta-storage metrics.
##
##          Features:
##          - Waterfall Rotation (Hourly -> Daily -> Weekly -> Monthly -> Yearly)
##          - Hardlink deduplication via rsync
##          - Mandatory filesystem boundary protection (-x / --one-file-system)
##          - Precise storage metrics (Total vs. Delta size) via LC_ALL=C parsing
##          - Smart purging based on disk pressure and historical delta size
##          - Atomic directory swaps
##          - Explicit logging of promotion strategies (MOVE vs. COPY)
##
## @author  Original by Thorsten Schnebeck, Refactored by Gemini
## @version 55.0 (Enhanced Logging)
## @license GPLv3
# ==============================================================================

set -euo pipefail

# ==============================================================================
# CONSTANTS & DEFAULTS
# ==============================================================================

SCRIPT_VERSION="55.0"
EXPECTED_CONFIG_VERSION="1.4"

CONFIG_FILE="/etc/snapshot-backup.conf"
LOGFILE="/var/log/snapshot-backup.log"
LOGTAG="snapshot-backup"
PIDFILE="/var/run/snapshot-backup.pid"

RUN_MODE="AUTO"
HAS_LOCK=false
INTERVALS=("hourly" "daily" "weekly" "monthly" "yearly")

# Hard Defaults
DEFAULT_BACKUP_ROOT="/backup"
DEFAULT_SOURCE_DIRS=("/")
DEFAULT_EXCLUDE_PATTERNS=(
    ".cache"
    "*.tmp"
    ".thumbnails"
    "swapfile"
    "node_modules"
    ".git"
    "lost+found"
    "Trash"
    ".Trash"
    "/var/lib/snapd/snaps/*.snap"
    "/var/lib/snapd/cache/*"
)
DEFAULT_EXCLUDE_MOUNTPOINTS=(
    "/proc"
    "/sys"
    "/dev"
    "/run"
    "/tmp"
    "/mnt"
    "/media"
    "/backup"
    "/snap"
    "/var/lib/docker/overlay2"
    "/var/lib/containers"
)

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

## @brief Logs a message to stdout or syslog/logfile depending on RUN_MODE.
## @param msg The message string to log.
log() {
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ "$RUN_MODE" == "SERVICE" ]; then
        if [ ! -d "$(dirname "$LOGFILE")" ]; then
            mkdir -p "$(dirname "$LOGFILE")"
        fi
        echo "[$timestamp] $msg" >> "$LOGFILE"
        logger -t "$LOGTAG" -p user.info -- "$msg"
    else
        echo ":: $msg"
    fi
}

## @brief Sanitizes input to ensure it is a valid integer.
## @param val Input string.
## @return Integer or 0 if invalid.
sanitize_int() {
    local val=${1:-0}
    val="${val//[^0-9]/}"
    if [ -z "$val" ]; then
        echo "0"
    else
        echo "$val"
    fi
}

## @brief Dumps a bash array for configuration generation.
## @param var_name The name of the array variable.
dump_config_array() {
    local var_name="$1"
    local -n arr=$var_name
    echo "$var_name=("
    for item in "${arr[@]}"; do
        echo "    \"$item\""
    done
    echo ")"
}

## @brief Error handler called on ERR trap.
## @param line_no The line number where the error occurred.
handle_error() {
    local exit_code=$?
    local line_no=$1
    if [ "$exit_code" -ne 0 ] && [ "$RUN_MODE" == "SERVICE" ]; then
        echo "❌ BACKUP FAILED (Code $exit_code) at line $line_no. See $LOGFILE" >&2
        logger -t "$LOGTAG" -p user.err "❌ BACKUP FAILED (Code $exit_code)"
    fi
    cleanup
}

## @brief Cleanup routine to remove PID files and temp files.
cleanup() {
    if [ "$HAS_LOCK" = true ] && [ -f "$PIDFILE" ]; then
        if [ "$(cat "$PIDFILE" 2>/dev/null)" == "$$" ]; then
            rm -f "$PIDFILE"
        fi
    fi
    if [ -n "${TEMP_EXCLUDE_FILE:-}" ] && [ -f "$TEMP_EXCLUDE_FILE" ]; then
        rm -f "$TEMP_EXCLUDE_FILE"
    fi
}

trap 'handle_error $LINENO' ERR
trap cleanup EXIT INT TERM

# ==============================================================================
# CONFIGURATION LOGIC
# ==============================================================================

## @brief Loads configuration from file and applies defaults.
## @param config_file Path to configuration file.
load_config() {
    local config_file=$1
    SOURCE_DIRS=()
    EXCLUDE_PATTERNS=()
    EXCLUDE_MOUNTPOINTS=()
    
    if [ -f "$config_file" ]; then
        source "$config_file"
    fi
    
    # Configuration Load with Defaults (Vertical for readability)
    RETAIN_HOURLY=$(sanitize_int "${RETAIN_HOURLY:-0}")
    RETAIN_DAILY=$(sanitize_int "${RETAIN_DAILY:-7}")
    RETAIN_WEEKLY=$(sanitize_int "${RETAIN_WEEKLY:-4}")
    RETAIN_MONTHLY=$(sanitize_int "${RETAIN_MONTHLY:-12}")
    RETAIN_YEARLY=$(sanitize_int "${RETAIN_YEARLY:-0}")
    SPACE_LOW_LIMIT_GB=$(sanitize_int "${SPACE_LOW_LIMIT_GB:-0}")
    SMART_PURGE_SLOTS=$(sanitize_int "${SMART_PURGE_SLOTS:-0}")
    
    BACKUP_ROOT="${BACKUP_ROOT:-$DEFAULT_BACKUP_ROOT}"
    BACKUP_DIR_PREFIX="${BACKUP_DIR_PREFIX:-}"
    
    if [ ${#SOURCE_DIRS[@]} -eq 0 ]; then
        SOURCE_DIRS=("${DEFAULT_SOURCE_DIRS[@]}")
    fi
    if [ ${#EXCLUDE_PATTERNS[@]} -eq 0 ]; then
        EXCLUDE_PATTERNS=("${DEFAULT_EXCLUDE_PATTERNS[@]}")
    fi
    if [ ${#EXCLUDE_MOUNTPOINTS[@]} -eq 0 ]; then
        EXCLUDE_MOUNTPOINTS=("${DEFAULT_EXCLUDE_MOUNTPOINTS[@]}")
    fi

    LOG_PROGRESS_INTERVAL="${LOG_PROGRESS_INTERVAL:-60}"
    # Default is empty here. Mandatory -x is enforced in create_rsync_snapshot.
    RSYNC_EXTRA_OPTS="${RSYNC_EXTRA_OPTS:-}"
}

## @brief Prints current configuration to stdout.
show_config() {
    cat << EOF
# ==============================================================================
# Configuration for snapshot-backup.sh
# ==============================================================================
# Generated by snapshot-backup v$SCRIPT_VERSION --show-config
# Save to: /etc/snapshot-backup.conf
# ==============================================================================
CONFIG_VERSION="$EXPECTED_CONFIG_VERSION"

# Retention Policy
RETAIN_HOURLY=$RETAIN_HOURLY
RETAIN_DAILY=$RETAIN_DAILY
RETAIN_WEEKLY=$RETAIN_WEEKLY
RETAIN_MONTHLY=$RETAIN_MONTHLY
RETAIN_YEARLY=$RETAIN_YEARLY

# Storage Management
SMART_PURGE_SLOTS=$SMART_PURGE_SLOTS
BACKUP_ROOT="$BACKUP_ROOT"
BACKUP_DIR_PREFIX="$BACKUP_DIR_PREFIX"

# Paths
$(dump_config_array SOURCE_DIRS)
$(dump_config_array EXCLUDE_PATTERNS)
$(dump_config_array EXCLUDE_MOUNTPOINTS)

# Settings
LOGFILE="$LOGFILE"
LOG_PROGRESS_INTERVAL=$LOG_PROGRESS_INTERVAL
RSYNC_EXTRA_OPTS="$RSYNC_EXTRA_OPTS"
EOF
    exit 0
}

# ==============================================================================
# PROCESS MANAGEMENT (LOCKING & KILL)
# ==============================================================================

## @brief Acquires execution lock via PID file.
acquire_lock() {
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "ERROR: Backup already running (PID: $pid)."
            exit 1
        else
            log "WARNING: Found stale PID file ($pid). Assuming crashed previous run."
        fi
    fi
    echo $$ > "$PIDFILE"
    HAS_LOCK=true
}

## @brief Terminates existing backup processes.
kill_active_backups() {
    set +e
    log "WARNING: Stopping active backup processes..."
    
    if systemctl is-active --quiet backup-job; then
        [ "$RUN_MODE" == "INTERACTIVE" ] && echo "Stopping systemd unit..."
        systemctl stop backup-job
        systemctl reset-failed backup-job 2>/dev/null || true
    fi
    
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            [ "$RUN_MODE" == "INTERACTIVE" ] && echo "Sending SIGTERM..."
            kill -15 "$pid"
            local c=10
            if [ "$RUN_MODE" == "INTERACTIVE" ]; then echo -n "Waiting: "; fi
            while [ $c -gt 0 ]; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    if [ "$RUN_MODE" == "INTERACTIVE" ]; then echo " Done."; fi
                    log "SUCCESS: Processes stopped gracefully."
                    break
                fi
                if [ "$RUN_MODE" == "INTERACTIVE" ]; then echo -n "$c.. "; fi
                sleep 1
                c=$((c-1))
            done
            if [ "$RUN_MODE" == "INTERACTIVE" ]; then echo ""; fi
            
            if kill -0 "$pid" 2>/dev/null; then
                log "WARNING: Force killing PID $pid..."
                kill -9 "$pid"
            fi
        fi
        rm -f "$PIDFILE"
    fi
    pkill -f "$(basename "$0")" 2>/dev/null || true
    [ -n "${BACKUP_ROOT:-}" ] && cleanup_stale_data
    log "STOPPED: All instances terminated."
    exit 0
}

# ==============================================================================
# STATUS & METRICS
# ==============================================================================

read_timestamp() {
    local file="$1"
    if [ ! -f "$file" ]; then echo "0"; return; fi
    local date_str
    date_str=$(head -n 1 "$file")
    date -d "$date_str" +%s 2>/dev/null || echo "0"
}

calc_time_ago() {
    local diff=$(( $(date +%s) - $1 ))
    if [ $diff -lt 60 ]; then echo "${diff}s ago";
    elif [ $diff -lt 3600 ]; then echo "$((diff/60))m ago";
    elif [ $diff -lt 86400 ]; then echo "$((diff/3600))h ago";
    else echo "$((diff/86400)) days ago"; fi
}

get_disk_usage() { df -BG "$BACKUP_ROOT" | awk 'NR==2 {print $4}' | tr -d 'G'; }
get_disk_free_kb() { df -k "$BACKUP_ROOT" | awk 'NR==2 {print $4}'; }

send_desktop_notification() {
    local title="$1"
    local body="$2"
    local icon="${3:-drive-harddisk}"
    local urgency="${4:-normal}"
    
    if ! command -v notify-send >/dev/null; then return; fi
    for user_dir in /run/user/*; do
        if [ -d "$user_dir" ]; then
            local uid
            uid=$(basename "$user_dir")
            local bus_address="unix:path=$user_dir/bus"
            if [ -S "$user_dir/bus" ]; then
                sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="$bus_address" XDG_RUNTIME_DIR="$user_dir" \
                    notify-send -u "$urgency" -i "$icon" -a "Backup System" "$title" "$body" 2>/dev/null || true
            fi
        fi
    done
}

is_backup_running() {
    if systemctl is-active --quiet backup-job; then return 0; fi
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if [ "$pid" == "$$" ]; then return 1; fi
        if kill -0 "$pid" 2>/dev/null; then return 0; fi
    fi
    return 1
}

status_desktop() {
    if is_backup_running; then send_desktop_notification "Backup Running" "Active." "system-run"; return; fi
    if ! mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then send_desktop_notification "Backup Idle" "Unmounted." "network-offline" "low"; return; fi
    if [ -d "$BACKUP_ROOT/daily.0.tmp" ]; then send_desktop_notification "Warning" "Stale data." "dialog-warning" "critical"; return; fi
    
    local ts_file="$BACKUP_ROOT/daily.0/.backup_timestamp"
    if [ -f "$ts_file" ]; then
        local ts
        ts=$(read_timestamp "$ts_file")
        send_desktop_notification "Backup Healthy" "Last: $(calc_time_ago "$ts")" "security-high"
    else
        send_desktop_notification "Backup Unknown" "No snapshots." "dialog-information"
    fi
}

show_status() {
    echo "================================================================================"
    echo "                  SNAPSHOT BACKUP STATUS (v$SCRIPT_VERSION)"
    echo "================================================================================"
    
    local state_color="\033[1;30m" 
    local state_text="STOPPED"
    local pid_info=""
    
    if systemctl is-active --quiet backup-job; then
        state_color="\033[1;32m"
        state_text="ACTIVE"
        pid_info="(backup-job.service)"
    elif [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            state_color="\033[1;32m"
            state_text="RUNNING"
            pid_info="(PID: $pid)"
        else
            state_color="\033[1;31m"
            state_text="CRASHED"
            pid_info="(Stale PID file: $pid)"
        fi
    fi
    
    echo -e "PROCESS:      ${state_color}● ${state_text}\033[0m $pid_info"

    if mountpoint -q "$BACKUP_ROOT" 2>/dev/null; then
        echo -e "STORAGE:      \033[1;32m● MOUNTED\033[0m ($BACKUP_ROOT)"
        
        local free_gb
        free_gb=$(get_disk_usage)
        echo "  Free Space:     ${free_gb} GB"
        
        local total_delta_kb=0
        local count=0
        local latest_size_gb="N/A"
        
        echo ""
        echo "LATEST SNAPSHOTS:"
        printf "%-10s %-22s %-15s %-15s\n" "Interval" "Timestamp" "Age" "Est. Size"
        echo "----------------------------------------------------------------------"
        
        for i in "${INTERVALS[@]}"; do
            local var="RETAIN_${i^^}"
            if [ "${!var}" -gt 0 ]; then
                local ts_file="$BACKUP_ROOT/$i.0/.backup_timestamp"
                local sz_file="$BACKUP_ROOT/$i.0/.backup_stats"
                if [ -f "$ts_file" ]; then
                    local ts
                    ts=$(read_timestamp "$ts_file")
                    local sz_info="-"
                    
                    if [ -f "$sz_file" ]; then
                        local stats
                        stats=$(cat "$sz_file")
                        local full_kb=${stats%:*}
                        local delta_kb=${stats#*:}
                        sz_info="~ $((delta_kb / 1024)) MB (Delta)"
                        
                        if [ "$delta_kb" -gt 0 ]; then
                            total_delta_kb=$((total_delta_kb + delta_kb))
                            count=$((count + 1))
                        fi
                        if [ "$i" == "daily" ]; then latest_size_gb="$((full_kb / 1024 / 1024)) GB"; fi
                    fi
                    
                    printf "%-10s %-22s %-15s %-15s\n" "$i.0" "$(head -n 1 "$ts_file")" "$(calc_time_ago "$ts")" "$sz_info"
                else
                    printf "%-10s %-22s %-15s %-15s\n" "$i.0" "MISSING" "-" "-"
                fi
            fi
        done
        
        echo ""
        if [ "$count" -gt 0 ]; then
            local avg_delta_mb=$((total_delta_kb / count / 1024))
            if [ "$avg_delta_mb" -eq 0 ]; then avg_delta_mb=1; fi
            local runway=$((free_gb * 1024 / avg_delta_mb))
            echo "METRICS:"
            echo "  Full Backup:    $latest_size_gb"
            echo "  Avg. Change:    ~$avg_delta_mb MB / Snapshot"
            echo "  Est. Capacity:  ~$runway more snapshots possible"
        fi

        if [ -d "$BACKUP_ROOT/daily.0.tmp" ]; then
            echo ""
            if [ "$(is_backup_running)" == "0" ]; then
                echo -e "WARNING:      \033[1;31m● STALE DATA DETECTED\033[0m (daily.0.tmp exists but process is stopped)"
            else
                echo -e "STATUS:       \033[1;34m● IN PROGRESS\033[0m (Writing to daily.0.tmp)"
            fi
        fi
    else
        echo -e "STORAGE:      \033[1;31m● NOT MOUNTED\033[0m"
    fi
    echo ""
    echo "RECENT LOGS ($LOGFILE):"
    echo "--------------------------------------------------------"
    if [ -f "$LOGFILE" ]; then tail -n 5 "$LOGFILE"; else echo "No logfile."; fi
    echo ""
}

log_summary() {
    local created=()
    local now
    now=$(date +%s)
    for interval in "${INTERVALS[@]}"; do
        local ts_file="$BACKUP_ROOT/$interval.0/.backup_timestamp"
        if [ -f "$ts_file" ]; then
            if [ $((now - $(read_timestamp "$ts_file"))) -lt 300 ]; then created+=("$interval.0"); fi
        fi
    done
    
    local msg="BACKUP FINISHED. System up-to-date."
    if [ ${#created[@]} -gt 0 ]; then msg="BACKUP SUCCESSFUL. Generated: ${created[*]}."; fi
    
    if [ "$RUN_MODE" == "SERVICE" ]; then
        echo -e "\n======================================================================\n[$(date '+%Y-%m-%d %H:%M:%S')] $msg\n======================================================================\n" >> "$LOGFILE"
        logger -t "$LOGTAG" -p user.notice -- "✅ $msg"
    else
        echo -e "\n ✅ $msg \n"
    fi
}

# ==============================================================================
# SAFETY & CLEANUP
# ==============================================================================

cleanup_stale_data() {
    find "$BACKUP_ROOT" -maxdepth 1 -name "*.tmp" -type d | while read -r d; do
        log "CLEANUP: Removing stale $d..."
        rm -rf "$d" 2>/dev/null || log "WARNING: Failed to delete $d (RO?)"
    done
}

## @brief Checks available disk space and removes oldest snapshots if critical.
check_disk_space_and_purge() {
    if [ "$SMART_PURGE_SLOTS" -le 0 ]; then return; fi
    
    local free_kb
    free_kb=$(get_disk_free_kb)
    local min_req_kb=10000000 
    
    # Refine using stats from daily.0 if available
    if [ -f "$BACKUP_ROOT/daily.0/.backup_stats" ]; then
        local stats
        stats=$(cat "$BACKUP_ROOT/daily.0/.backup_stats")
        local delta_kb=${stats#*:}
        min_req_kb=$((delta_kb * SMART_PURGE_SLOTS))
        if [ "$min_req_kb" -lt 5000000 ]; then min_req_kb=5000000; fi
        log "INFO: Smart purge buffer set to $((min_req_kb / 1024)) MB (based on delta history)."
    fi
    
    if [ "$free_kb" -ge "$min_req_kb" ]; then return; fi
    
    log "CRITICAL: Low Disk Space (Free: $((free_kb/1024)) MB < Req: $((min_req_kb/1024)) MB). Initiating Rolling Delete..."
    local rev_intervals=("yearly" "monthly" "weekly" "daily" "hourly")
    for interval in "${rev_intervals[@]}"; do
        local indices
        indices=$(find "$BACKUP_ROOT" -maxdepth 1 -name "${interval}.*" -type d | sed "s/^.*${interval}\.//" | grep -E "^[0-9]+$" | sort -rn || true)
        for idx in $indices; do
            local path="$BACKUP_ROOT/$interval.$idx"
            log "PURGE: Deleting $path"
            rm -rf "$path"
            if [ "$(get_disk_free_kb)" -ge "$min_req_kb" ]; then log "SPACE OK."; return; fi
        done
    done
    log "WARNING: Purged all snapshots but space is still tight."
}

# ==============================================================================
# FILE SYSTEM OPERATIONS
# ==============================================================================

create_exclude_filter() {
    local source_dir=$1
    local clean_source="${source_dir%/}"
    TEMP_EXCLUDE_FILE=$(mktemp)
    
    if [ -n "${EXCLUDE_PATTERNS:-}" ]; then
        printf "%s\n" "${EXCLUDE_PATTERNS[@]}" >> "$TEMP_EXCLUDE_FILE"
    fi
    
    if [ -n "${EXCLUDE_MOUNTPOINTS:-}" ]; then
        for mountpoint in "${EXCLUDE_MOUNTPOINTS[@]}"; do
            if [[ "$mountpoint" == "$source_dir/"* ]] || [[ "$mountpoint" == "$source_dir" ]]; then
                local rel="${mountpoint#$clean_source}"
                rel="${rel#/}"
                if [ -n "$rel" ]; then echo "/${rel}" >> "$TEMP_EXCLUDE_FILE"; fi
            fi
        done
    fi
    
    if [[ "$BACKUP_ROOT" == "$source_dir"* ]]; then
        local rel="${BACKUP_ROOT#$clean_source}"
        rel="${rel#/}"
        if [ -n "$rel" ]; then echo "/${rel}" >> "$TEMP_EXCLUDE_FILE"; fi
    fi
}

create_mountpoint_dirs() {
    local snapshot_base=$1
    local source_dir=$2
    local target_base="$snapshot_base"
    if [ -n "$BACKUP_DIR_PREFIX" ]; then target="$target/$BACKUP_DIR_PREFIX"; fi

    if [ -z "${EXCLUDE_MOUNTPOINTS:-}" ]; then return; fi
    for mp in "${EXCLUDE_MOUNTPOINTS[@]}"; do
        if [[ "$mp" == "$source_dir/"* ]] || [[ "$mp" == "$source_dir" ]]; then
            local dest="$target_base$mp"
            if [ ! -d "$dest" ]; then
                mkdir -p "$dest"
                if [ -d "$mp" ]; then
                    chmod --reference="$mp" "$dest" 2>/dev/null || true
                    chown --reference="$mp" "$dest" 2>/dev/null || true
                fi
            fi
        fi
    done
}

# ==============================================================================
# DYNAMIC LOGIC
# ==============================================================================

get_retention() {
    local var="RETAIN_${1^^}"
    echo "${!var}"
}

get_min_age_sec() {
    case "$1" in
        hourly) echo 3000;;
        daily) echo 80000;;
        weekly) echo 345600;;
        monthly) echo 1209600;;
        yearly) echo 8000000;;
    esac
}

get_source_interval_for() {
    local target=$1
    local levels=("hourly" "daily" "weekly" "monthly" "yearly")
    local found_target=false
    for (( i=${#levels[@]}-1; i>=0; i-- )); do
        local lvl="${levels[$i]}"
        if [ "$lvl" == "$target" ]; then found_target=true; continue; fi
        if [ "$found_target" == true ]; then
             if [ "$(get_retention "$lvl")" -gt 0 ]; then echo "$lvl"; return; fi
        fi
    done
    echo "none"
}

get_oldest_index() {
    local interval=$1
    local idx
    idx=$(find "$BACKUP_ROOT" -maxdepth 1 -name "${interval}.*" -type d \
          | sed "s/^.*${interval}\.//" | grep -E "^[0-9]+$" | sort -rn | head -n 1 || true)
    if [ -z "$idx" ]; then echo "-1"; else echo "$idx"; fi
}

is_promotion_due() {
    local target=$1
    local source_ts=$2
    if [ ! -f "$BACKUP_ROOT/$target.0/.backup_timestamp" ]; then echo "true"; return; fi
    
    local last_target_ts
    last_target_ts=$(read_timestamp "$BACKUP_ROOT/$target.0/.backup_timestamp")
    local min_age
    min_age=$(get_min_age_sec "$target")
    local age_diff=$((source_ts - last_target_ts))
    
    case "$target" in
        hourly) [ "$age_diff" -ge "$min_age" ] && echo "true" || echo "false" ;;
        daily)  [ "$(date -d "@$source_ts" +%Y%m%d)" != "$(date -d "@$last_target_ts" +%Y%m%d)" ] && echo "true" || echo "false" ;;
        weekly) ([ "$(date -d "@$source_ts" +%G%V)" != "$(date -d "@$last_target_ts" +%G%V)" ] && [ "$age_diff" -ge 345600 ]) && echo "true" || echo "false" ;;
        monthly)([ "$(date -d "@$source_ts" +%Y%m)" != "$(date -d "@$last_target_ts" +%Y%m)" ] && [ "$age_diff" -ge 1209600 ]) && echo "true" || echo "false" ;;
        yearly) ([ "$(date -d "@$source_ts" +%Y)" != "$(date -d "@$last_target_ts" +%Y)" ] && [ "$age_diff" -ge 8000000 ]) && echo "true" || echo "false" ;;
    esac
}

check_promote() {
    local tgt=$1
    local force=$2
    local ret=$3
    
    local src
    src=$(get_source_interval_for "$tgt")
    if [ "$src" == "none" ]; then return; fi
    
    local s_idx
    s_idx=$(get_oldest_index "$src")
    if [ "$s_idx" -eq "-1" ]; then return; fi
    
    local src_path="$BACKUP_ROOT/$src.$s_idx"
    local src_ts
    src_ts=$(read_timestamp "$src_path/.backup_timestamp")
    
    # Check Idempotency
    if [ -f "$BACKUP_ROOT/$tgt.0/.backup_timestamp" ]; then
        local tgt_ts
        tgt_ts=$(read_timestamp "$BACKUP_ROOT/$tgt.0/.backup_timestamp")
        if [ "$src_ts" -eq "$tgt_ts" ]; then
             log "INFO: Promotion $src -> $tgt skipped (Already up to date)."
             return
        fi
    fi
    
    local promote=false
    if [ "$force" = true ]; then
        promote=true
    elif [ "$(is_promotion_due "$tgt" "$src_ts")" == "true" ]; then
        promote=true
    else
        # Verbose info if not due
        # log "INFO: Promotion $src -> $tgt not due yet."
        :
    fi
    
    if [ "$promote" = true ]; then
        local t_tmp="$BACKUP_ROOT/$tgt.0.tmp"
        rm -rf "$t_tmp"
        
        local src_retain
        src_retain=$(get_retention "$src")
        local method="UNKNOWN"
        local reason="UNKNOWN"
        
        # Determine Strategy Logic
        if [ "$force" = true ]; then
            method="COPY"
            reason="Forced by user"
        elif [ "$s_idx" -ge "$((src_retain - 1))" ]; then
            method="MOVE"
            reason="Source overflow (Index $s_idx >= Retention $src_retain)"
        else
            method="COPY"
            reason="Retention buffer (Index $s_idx < Retention $src_retain)"
        fi
        
        log "DECISION: Promoting $src.$s_idx -> $tgt.0 via [$method]. Reason: $reason"
        
        # Execute Action based on Strategy
        if [ "$method" == "MOVE" ]; then
             mv "$src_path" "$t_tmp"
        else
             cp -al "$src_path" "$t_tmp"
        fi
        
        # Metadata Link Fix
        if [ -f "$t_tmp/.backup_timestamp" ]; then rm "$t_tmp/.backup_timestamp"; fi
        if [ -f "$src_path/.backup_timestamp" ]; then cp "$src_path/.backup_timestamp" "$t_tmp/"; fi
        # Ensure stats are carried over
        if [ -f "$src_path/.backup_stats" ]; then cp "$src_path/.backup_stats" "$t_tmp/"; fi
        
        finalize_level "$tgt"
    fi
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

create_rsync_snapshot() {
    local interval=$1
    local link_dest=""
    local current_total_kb=0
    local current_xfer_kb=0
    
    log "--- Starting ${interval^} Backup ---"
    
    if [ -d "$BACKUP_ROOT/$interval.0" ]; then
        link_dest="--link-dest=$BACKUP_ROOT/$interval.0"
        log "INFO: Hardlinking against: $BACKUP_ROOT/$interval.0"
    else
        local fallback
        fallback=$(find "$BACKUP_ROOT" -maxdepth 1 -name "*.[0-9]*" -type d | head -n 1 || true)
        if [ -n "$fallback" ]; then
             link_dest="--link-dest=$fallback"
             log "INFO: Hardlinking against fallback: $fallback"
        else
             log "INFO: Creating full backup (First run)."
        fi
    fi
    
    local temp_dest="$BACKUP_ROOT/$interval.0.tmp"
    mkdir -p "$temp_dest"
    
    for source in "${SOURCE_DIRS[@]}"; do
        if [ ! -e "$source" ]; then log "WARNING: Source not found: $source"; continue; fi
        
        local dest_path="$temp_dest"
        if [ -n "$BACKUP_DIR_PREFIX" ]; then dest_path="$dest_path/$BACKUP_DIR_PREFIX"; fi
        dest_path="$dest_path${source}"
        
        mkdir -p "$(dirname "$dest_path")"
        create_exclude_filter "$source"
        
        # Mandatory Flags: -aAXH (Archive), -x (One Filesystem), --stats (Metrics)
        local rsync_opts="-aAXH --delete --numeric-ids -x --stats"
        [ -n "${RSYNC_EXTRA_OPTS:-}" ] && rsync_opts="$rsync_opts $RSYNC_EXTRA_OPTS"

        log "INFO: Processing Source: $source"
        
        # Run rsync with LC_ALL=C to guarantee English output for grep
        if [ "$LOG_PROGRESS_INTERVAL" -gt 0 ] && [ "$RUN_MODE" != "SILENT" ]; then
           local out_target
           if [ "$RUN_MODE" == "SERVICE" ]; then out_target="| logger -t $LOGTAG --"; else out_target="/dev/tty"; fi
           
           if [ "$RUN_MODE" == "SERVICE" ]; then
               LC_ALL=C rsync $rsync_opts --info=progress2 $link_dest --exclude-from="$TEMP_EXCLUDE_FILE" \
                   "$source/" "$dest_path/" 2>&1 \
                   | tr '\r' '\n' \
                   | awk -v interval="$LOG_PROGRESS_INTERVAL" 'BEGIN { last=0; } { if (length($0)<10) next; now=systime(); if (now-last>=interval) { print "[PROGRESS] "$0; fflush(); last=now; } } END { print "[DONE] "$0 }' \
                   | stdbuf -oL tee >(grep --line-buffered -v "^\[PROGRESS\]" >> "$LOGFILE") \
                   | logger -t "$LOGTAG" -- 2>/dev/null
           else
               LC_ALL=C rsync $rsync_opts --info=progress2 $link_dest --exclude-from="$TEMP_EXCLUDE_FILE" \
                   "$source/" "$dest_path/" 2>&1 \
                   | tr '\r' '\n' \
                   | awk -v interval="$LOG_PROGRESS_INTERVAL" 'BEGIN { last=0; } { if (length($0)<10) next; now=systime(); if (now-last>=interval) { print "[PROGRESS] "$0; fflush(); last=now; } } END { print "[DONE] "$0 }' \
                   | stdbuf -oL tee >(grep --line-buffered -v "^\[PROGRESS\]" >> "$LOGFILE") \
                   | stdbuf -oL tee /dev/tty
           fi
        else
           # Direct log append for silent/standard mode
           LC_ALL=C rsync $rsync_opts $link_dest --exclude-from="$TEMP_EXCLUDE_FILE" \
                "$source/" "$dest_path/" >> "$LOGFILE" 2>&1
        fi
        
        local ret=${PIPESTATUS[0]}
        if [ $ret -ne 0 ] && [ $ret -ne 24 ]; then
            log "ERROR: Rsync failed (Code $ret)"; rm -rf "$temp_dest"; exit $ret
        fi
        rm -f "$TEMP_EXCLUDE_FILE"
        create_mountpoint_dirs "$temp_dest" "$source"
        
        # PARSE STATS FROM LOGFILE (Reliable due to LC_ALL=C)
        local tail_log
        tail_log=$(tail -n 50 "$LOGFILE")
        local t_size
        t_size=$(echo "$tail_log" | grep "Total file size:" | head -n 1 | tr -d ',' | tr -d '.' | awk '{print $4}')
        local x_size
        x_size=$(echo "$tail_log" | grep "Total transferred file size:" | head -n 1 | tr -d ',' | tr -d '.' | awk '{print $5}')
        
        if [ -n "$t_size" ]; then current_total_kb=$((current_total_kb + t_size / 1024)); fi
        if [ -n "$x_size" ]; then current_xfer_kb=$((current_xfer_kb + x_size / 1024)); fi
    done
    
    date '+%Y-%m-%d %H:%M:%S' > "$temp_dest/.backup_timestamp"
    # SAVE METRICS: TOTAL_KB:DELTA_KB
    echo "${current_total_kb}:${current_xfer_kb}" > "$temp_dest/.backup_stats"
    
    log "SUCCESS: Rsync completed. Delta: $((current_xfer_kb/1024)) MB."
}

finalize_level() {
    local int=$1
    if [ ! -d "$BACKUP_ROOT/$int.0.tmp" ]; then return; fi
    
    local indices=()
    while IFS= read -r line; do
        indices+=("$line")
    done < <(find "$BACKUP_ROOT" -maxdepth 1 -name "${int}.*" -type d | sed "s/^.*\.//" | grep -E "^[0-9]+$" | sort -rn || true)
    
    local retain
    retain=$(get_retention "$int")
    
    for idx in "${indices[@]}"; do
        local path="$BACKUP_ROOT/$int.$idx"
        local next=$((idx+1))
        if [ "$next" -ge "$retain" ]; then
            rm -rf "$path"
        else
            mv "$path" "$BACKUP_ROOT/$int.$next"
        fi
    done
    mv "$BACKUP_ROOT/$int.0.tmp" "$BACKUP_ROOT/$int.0"
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --show-config          Print configuration to stdout.
  -c, --config FILE      Load specific config file.
  --status               Show status report.
  --desktop              Send desktop notification.
  -f, --force-weekly     Force weekly promotion.
  -m, --force-monthly    Force monthly promotion.
  -y, --force-yearly     Force yearly promotion.
  -k, --kill             Stop running backups.
  -s, --service          Force Service Mode (Log to file/syslog).
  -h, --help             Show this help.
EOF
    exit 0
}

main() {
    # Variable Declarations (Vertical)
    local custom_config=""
    local force_weekly=false
    local force_monthly=false
    local force_yearly=false
    local do_kill=false
    local do_status=false
    local do_desktop=false
    local show_conf=false
    local explicit_service=false
    local perform_backup=false
    
    if [ $# -eq 0 ]; then
        RUN_MODE="SERVICE"
    else
        RUN_MODE="INTERACTIVE"
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --show-config) show_conf=true; shift ;;
            --status) do_status=true; shift ;;
            --desktop) do_desktop=true; shift ;;
            -c|--config) custom_config="$2"; shift 2 ;;
            -f|--force-weekly) force_weekly=true; shift ;;
            -m|--force-monthly) force_monthly=true; shift ;;
            -y|--force-yearly) force_yearly=true; shift ;;
            -k|--kill) do_kill=true; shift ;;
            -s|--service) explicit_service=true; shift ;;
            -h|--help) show_help ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [ "$explicit_service" = true ]; then RUN_MODE="SERVICE"; fi
    if [ -n "$custom_config" ]; then CONFIG_FILE="$custom_config"; fi
    
    if [ "$do_kill" = true ]; then
        load_config "$CONFIG_FILE"
        kill_active_backups
    fi
    
    load_config "$CONFIG_FILE"
    
    if [ "$show_conf" = true ]; then show_config; fi
    
    # Check if a backup run is actually requested/needed
    if [ "$force_weekly" = true ] || [ "$force_monthly" = true ] || [ "$force_yearly" = true ]; then
        perform_backup=true
    fi
    if [ "$do_status" = false ] && [ "$do_desktop" = false ] && [ "$do_kill" = false ] && [ "$show_conf" = false ] && [ "$perform_backup" = false ]; then
        perform_backup=true
    fi
    
    if [ "$perform_backup" = true ]; then
        if [ "$RUN_MODE" == "SERVICE" ]; then mkdir -p "$(dirname "$LOGFILE")"; fi
        mkdir -p "$BACKUP_ROOT"
        
        acquire_lock
        
        log "--- Starting snapshot-backup v$SCRIPT_VERSION ---"
        
        cleanup_stale_data
        check_disk_space_and_purge
        
        local base=""
        for i in "${INTERVALS[@]}"; do
            if [ "$(get_retention "$i")" -gt 0 ]; then
                base="$i"
                break
            fi
        done
        if [ -z "$base" ]; then
            log "Error: No retention enabled."
            exit 1
        fi
        
        local rev_intervals=("yearly" "monthly" "weekly" "daily" "hourly")
        for i in "${rev_intervals[@]}"; do
            if [ "$i" == "$base" ]; then break; fi
            if [ "$(get_retention "$i")" -gt 0 ]; then
                 local force_flag="false"
                 if [ "$i" == "yearly" ]; then force_flag="$force_yearly"; fi
                 if [ "$i" == "monthly" ]; then force_flag="$force_monthly"; fi
                 if [ "$i" == "weekly" ]; then force_flag="$force_weekly"; fi
                 check_promote "$i" "$force_flag" "$(get_retention "$i")"
            fi
        done
        
        local run_base=false
        local now
        now=$(date +%s)
        
        if [ -f "$BACKUP_ROOT/$base.0/.backup_timestamp" ]; then
            local last_ts
            last_ts=$(read_timestamp "$BACKUP_ROOT/$base.0/.backup_timestamp")
            if [ "$(is_promotion_due "$base" "$now")" == "true" ]; then
                run_base=true
            else
                log "INFO: Base backup ($base) not due yet."
            fi
        else
            run_base=true
        fi
        
        if [ "$run_base" = true ]; then
            create_rsync_snapshot "$base"
            finalize_level "$base"
            log_summary
            
            local dispatcher_script="/etc/NetworkManager/dispatcher.d/30-backup-control.sh"
            if [ -x "$dispatcher_script" ]; then
                if [ "$RUN_MODE" == "SERVICE" ]; then
                    "$dispatcher_script" "none" "backup-finished" >/dev/null 2>&1
                else
                    echo ":: Backup complete. Storage left mounted for inspection."
                fi
            fi
        fi
    fi
    
    if [ "$do_desktop" = true ]; then status_desktop; fi
    if [ "$do_status" = true ]; then show_status; fi
}

main "$@"

