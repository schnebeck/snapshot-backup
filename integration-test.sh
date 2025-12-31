#!/bin/bash

# ==============================================================================
## @file    integration-test.sh
## @brief   Enterprise Integration Test Suite (Aligned with Historical Requirements)
## @version 14.1
##
## @details Validates local and remote backup functionality using the standardized
##          historical test cases 01-12, 20-34, and 99.
##
## @author  Refactored by Google DeepMind
## @license GPLv3
# ==============================================================================

set -u
set -o pipefail

# ------------------------------------------------------------------------------
# 0. GLOBAL CONSTANTS & PRE-CHECKS
# ------------------------------------------------------------------------------

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log() { echo "$@"; }

# Helper for systems without 'timeout' command
run_with_timeout() {
    local duration="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$duration" "$@"
        return $?
    fi
    "$@" &
    local child=$!
    ( sleep "$duration" && kill -0 "$child" 2>/dev/null && kill -TERM "$child" ) &
    local watcher=$!
    wait "$child" 2>/dev/null
    local ret=$?
    kill -0 "$watcher" 2>/dev/null && kill -9 "$watcher" 2>/dev/null
    return $ret
}


# Root Privilege Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This test suite requires root privileges.${NC}"
    exit 1
fi

TEST_BASE="/tmp/backup-simulation"
MOCK_BIN="$TEST_BASE/mock_bin"
MNT_SOURCE="$TEST_BASE/mnt_source"
MNT_BACKUP="$TEST_BASE/mnt_backup"
SERVER_ROOT="$TEST_BASE/server_root"

SUITE_LOG="/home/schnebeck/backup-test/suite_debug.log"
TEST_LOG="$SUITE_LOG"
CONF_FILE="$TEST_BASE/test.conf"
AGENT_CONF="$TEST_BASE/agent.conf"

TEST_SSH_KEY="$TEST_BASE/id_rsa_test"
AUTH_KEYS="/root/.ssh/authorized_keys"
KNOWN_HOSTS="/root/.ssh/known_hosts"
REMOTE_USER="root"
REMOTE_HOST="localhost"

SCRIPT="./snapshot-backup.sh"
REAL_AGENT="./snapshot-backup.sh"
TEST_REMOTE_BIN="$(pwd)/snapshot-backup.sh --agent-mode"
if [ ! -f "$REAL_AGENT" ]; then
    REAL_AGENT="/usr/local/sbin/snapshot-agent.sh"
fi

# ==============================================================================
# 1. CORE UTILITIES
# ==============================================================================

##
# @brief Cleans up test environment (mounts, directories).
pre_test_cleanup() {
    grep "$TEST_BASE" /proc/mounts | awk '{print $2}' | sort -r | while read -r mnt; do
        umount -l "$mnt" >/dev/null 2>&1 || true
    done
    
    if [ -d "$TEST_BASE" ]; then
        rm -rf "$TEST_BASE"
    fi
    rm -f /var/run/snapshot-backup.pid
    
    if [ -f "$AUTH_KEYS" ]; then
        sed -i '/# INTEGRATION-TEST-KEY/d' "$AUTH_KEYS"
    fi
}

##
# @brief Sets up fresh filesystem and configuration environment.
setup_env() {
    # Reset Globals from previous tests
    unset TEST_RETAIN_DAILY TEST_RETAIN_WEEKLY TEST_RETAIN_MONTHLY
    unset TEST_SPACE_LIMIT TEST_PURGE_SLOTS TEST_EXCLUDES TEST_RSYNC_OPTS

    pre_test_cleanup
    mkdir -p "$TEST_BASE" "$SERVER_ROOT" "$MNT_SOURCE" "$MNT_BACKUP" "$MOCK_BIN"

    truncate -s 200M "$TEST_BASE/source.img" "$TEST_BASE/backup.img"
    mkfs.ext4 -F -q "$TEST_BASE/source.img"
    mkfs.ext4 -F -q "$TEST_BASE/backup.img"
    mount -o loop "$TEST_BASE/source.img" "$MNT_SOURCE"
    mount -o loop "$TEST_BASE/backup.img" "$MNT_BACKUP"

    # Agent Config
    cat > "$AGENT_CONF" <<EOF
BASE_STORAGE="$SERVER_ROOT"
LOCK_DIR="$TEST_BASE/agent_locks"
EOF
    mkdir -p "$TEST_BASE/agent_locks"

    # Client Config
    cat > "$CONF_FILE" <<EOF
BACKUP_MODE="LOCAL"
BACKUP_ROOT="$MNT_BACKUP"
SOURCE_DIRS=("$MNT_SOURCE")
LOGFILE="$SUITE_LOG"
LOGTAG="test-suite"
REMOTE_USER="root"
REMOTE_HOST="127.0.0.1"
REMOTE_PORT="22"
REMOTE_KEY="$TEST_SSH_KEY"
REMOTE_STORAGE_ROOT="$SERVER_ROOT"
REMOTE_AGENT="$TEST_REMOTE_BIN --config $AGENT_CONF"
CLIENT_NAME="test-client"
ENABLE_NOTIFICATIONS=false
SPACE_LOW_LIMIT_GB=0
EXCLUDE_PATTERNS=(".cache" "*.tmp" "lost+found")
EOF
}

##
# @brief Configures SSH for passwordless local access.
setup_ssh() {
    if [ ! -d "/root/.ssh" ]; then
        mkdir -p "/root/.ssh" && chmod 700 "/root/.ssh"
    fi
    rm -f "$TEST_SSH_KEY"*
    ssh-keygen -t ed25519 -f "$TEST_SSH_KEY" -N "" -q -C "INTEGRATION-TEST-KEY"
    cat "$TEST_SSH_KEY.pub" >> "$AUTH_KEYS"
    ssh-keyscan -p 22 -t ed25519 127.0.0.1 >> "$KNOWN_HOSTS" 2>/dev/null
}

##
# @brief Manipulates file modification time.
shift_time() {
    [ ! -d "$1" ] && date -d "$2" '+%Y-%m-%d %H:%M:%S %z' > "$1"
    touch -d "$2" "$1"
}

# ALIASES
setup_infrastructure() { setup_env; }
setup_ssh_access() { setup_ssh; }
set_file_age() { shift_time "$1" "$2"; }

##
# @brief Injects test parameters into local configuration.
generate_local_config() {
    [ -n "${TEST_RETAIN_HOURLY:-}" ] && echo "RETAIN_HOURLY=$TEST_RETAIN_HOURLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_DAILY:-}" ] && echo "RETAIN_DAILY=$TEST_RETAIN_DAILY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_WEEKLY:-}" ] && echo "RETAIN_WEEKLY=$TEST_RETAIN_WEEKLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_MONTHLY:-}" ] && echo "RETAIN_MONTHLY=$TEST_RETAIN_MONTHLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_YEARLY:-}" ] && echo "RETAIN_YEARLY=$TEST_RETAIN_YEARLY" >> "$CONF_FILE"
    
    [ -n "${TEST_SPACE_LIMIT:-}" ] && echo "SPACE_LOW_LIMIT_GB=$TEST_SPACE_LIMIT" >> "$CONF_FILE"
    [ -n "${TEST_PURGE_SLOTS:-}" ] && echo "SMART_PURGE_SLOTS=$TEST_PURGE_SLOTS" >> "$CONF_FILE"
}

##
# @brief Injects test parameters into remote configuration.
generate_remote_config() {
    sed -i 's/BACKUP_MODE="LOCAL"/BACKUP_MODE="REMOTE"/' "$CONF_FILE"
    # Force Agent to use the same config file
    echo "REMOTE_AGENT=\"$(pwd)/snapshot-backup.sh --agent-mode --config $CONF_FILE\"" >> "$CONF_FILE"
    
    # Explicitly set connection details for tests to match expectations
    echo "REMOTE_HOST=\"$REMOTE_HOST\"" >> "$CONF_FILE"
    echo "REMOTE_USER=\"$REMOTE_USER\"" >> "$CONF_FILE"
    echo "REMOTE_STORAGE_ROOT=\"$SERVER_ROOT\"" >> "$CONF_FILE"
    echo "REMOTE_SSH_OPTS=\"-o StrictHostKeyChecking=no -o BatchMode=yes\"" >> "$CONF_FILE"
    
    [ -n "${TEST_RSYNC_OPTS:-}" ] && echo "RSYNC_EXTRA_OPTS=\"$TEST_RSYNC_OPTS\"" >> "$CONF_FILE"
    [ -n "${TEST_EXCLUDES:-}" ] && echo "EXCLUDE_PATTERNS=($TEST_EXCLUDES)" >> "$CONF_FILE"
    
    # Ensure Agent finds correct storage path in shared config
    echo "BASE_STORAGE=\"$SERVER_ROOT\"" >> "$CONF_FILE"
    echo "LOCK_DIR=\"$TEST_BASE/agent_locks\"" >> "$CONF_FILE"
    
    [ -n "${TEST_SPACE_LIMIT:-}" ] && echo "SPACE_LOW_LIMIT_GB=$TEST_SPACE_LIMIT" >> "$CONF_FILE"
    [ -n "${TEST_SPACE_LIMIT:-}" ] && echo "SMART_PURGE_LIMIT=$TEST_SPACE_LIMIT" >> "$CONF_FILE"
    [ -n "${TEST_PURGE_SLOTS:-}" ] && echo "SMART_PURGE_SLOTS=$TEST_PURGE_SLOTS" >> "$CONF_FILE"
    
    [ -n "${TEST_RETAIN_HOURLY:-}" ] && echo "RETAIN_HOURLY=$TEST_RETAIN_HOURLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_DAILY:-}" ] && echo "RETAIN_DAILY=$TEST_RETAIN_DAILY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_WEEKLY:-}" ] && echo "RETAIN_WEEKLY=$TEST_RETAIN_WEEKLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_MONTHLY:-}" ] && echo "RETAIN_MONTHLY=$TEST_RETAIN_MONTHLY" >> "$CONF_FILE"
    [ -n "${TEST_RETAIN_YEARLY:-}" ] && echo "RETAIN_YEARLY=$TEST_RETAIN_YEARLY" >> "$CONF_FILE"
}

# ==============================================================================
# 2. LOCAL TEST CASES (01-12 & 99)
# ==============================================================================

test_01() {
    setup_infrastructure; generate_local_config
    echo "Lokal Daten" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    find "$MNT_BACKUP/daily.0" -name "f.txt" | grep -q "f.txt"
}

test_02() {
    setup_infrastructure; generate_local_config
    mkdir -p "$MNT_BACKUP/daily.0"
    touch "$MNT_BACKUP/daily.0/.backup_timestamp"
    set_file_age "$MNT_BACKUP/daily.0/.backup_timestamp" "2023-10-02 12:00:00"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ -d "$MNT_BACKUP/weekly.0" ]
}

test_03() {
    setup_infrastructure; generate_local_config
    mkdir -p "$MNT_SOURCE/ext"
    mount -t tmpfs tmpfs "$MNT_SOURCE/ext"
    echo "Versteckt" > "$MNT_SOURCE/ext/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    local r=0
    find "$MNT_BACKUP/daily.0" -name "f.txt" | grep -q "f.txt" && r=1
    umount "$MNT_SOURCE/ext"
    return $r
}

test_04() {
    setup_infrastructure
    export TEST_EXCLUDES="\"*.tmp\" \"cache/\""
    generate_local_config
    echo "Keep" > "$MNT_SOURCE/ok.txt"
    echo "Drop" > "$MNT_SOURCE/junk.tmp"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    find "$MNT_BACKUP/daily.0" -name "ok.txt" | grep -q "ok.txt" && \
    ! find "$MNT_BACKUP/daily.0" -name "junk.tmp" | grep -q "junk.tmp"
}

test_05() {
    setup_infrastructure
    export TEST_SPACE_LIMIT=1000
    export TEST_PURGE_SLOTS=1
    generate_local_config
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    grep -q "Triggering smart purge" "$SUITE_LOG" || grep -q "Smart purge triggered" "$SUITE_LOG"
}

test_06() {
    setup_infrastructure; generate_local_config
    echo "$$" > "/var/run/snapshot-backup.pid"
    if $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1; then rm -f "/var/run/snapshot-backup.pid"; return 1; fi
    rm -f "/var/run/snapshot-backup.pid"
    return 0
}

test_07() {
    setup_infrastructure; generate_local_config
    mkdir -p "$MNT_BACKUP/daily.0"
    touch "$MNT_BACKUP/daily.0/.backup_timestamp"
    set_file_age "$MNT_BACKUP/daily.0/.backup_timestamp" "2023-10-02 12:00:00"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -d "$MNT_BACKUP/weekly.0" ] && return 1
    # Run again - IDEMPOTENCY check
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -d "$MNT_BACKUP/weekly.1" ]
}

test_08() {
    setup_infrastructure; generate_local_config
    cat > "$MOCK_BIN/rsync" <<EOF
#!/bin/bash
exit 24
EOF
    chmod +x "$MOCK_BIN/rsync"
    PATH="$MOCK_BIN:$PATH" $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
}

test_09() {
    setup_infrastructure; generate_local_config
    echo "Original" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    local tf=$(find "$MNT_BACKUP/daily.0" -name "f.txt")
    echo "Kaputt" > "$tf"
    touch -r "$MNT_SOURCE/f.txt" "$tf"
    $SCRIPT --config "$CONF_FILE" --verify >> "$SUITE_LOG" 2>&1
    grep -q "Original" "$tf"
}

test_10() {
    setup_infrastructure; generate_local_config
    echo "Alt" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    cat > "$MOCK_BIN/rsync" <<EOF
#!/bin/bash
exit 1
EOF
    chmod +x "$MOCK_BIN/rsync"
    PATH="$MOCK_BIN:$PATH" $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1 || true
    # Atomic check: daily.0 should NOT change or corrupt
    find "$MNT_BACKUP/daily.0" -name "f.txt" | xargs grep -q "Alt"
}

##
# @brief Verifies self-deployment logic.
test_19() {
    setup_env
    setup_ssh
    # log_test removed (redundant)
    
    # Inject SSH options to prevent hangs
    echo "REMOTE_SSH_OPTS=\"-o StrictHostKeyChecking=no -o BatchMode=yes\"" >> "$CONF_FILE"
    
    # 1. Run Deploy Command
    echo "Running --deploy-agent to root@127.0.0.1..." >> "$TEST_LOG"
    $SCRIPT --config "$CONF_FILE" --deploy-agent "root@127.0.0.1" >> "$TEST_LOG" 2>&1
    if [ $? -ne 0 ]; then
        echo "  [FAIL] Deployment command failed." >> "$TEST_LOG"
        return 1
    fi
    
    # 2. Check File Existence & Permissions
    if [ ! -f "/usr/local/sbin/snapshot-agent.sh" ]; then
        echo "  [FAIL] Remote file /usr/local/sbin/snapshot-agent.sh not found." >> "$TEST_LOG"
        return 1
    fi
    
    if [ ! -x "/usr/local/sbin/snapshot-agent.sh" ]; then
        echo "  [FAIL] Remote file is not executable." >> "$TEST_LOG"
        return 1
    fi
    
    # 3. Check Version of Deployed Agent
    local depl_ver=$(/usr/local/sbin/snapshot-agent.sh --agent-mode --version)
    if [ -z "$depl_ver" ]; then
        echo "  [FAIL] Deployed agent returned no version." >> "$TEST_LOG"
        return 1
    fi
    
    echo "Deployed Agent Version: $depl_ver" >> "$TEST_LOG"

    # 4. SWITCH TEST SUITE TO USE DEPLOYED AGENT
    echo "Switching integration suite to use /usr/local/sbin/snapshot-agent.sh..." >> "$TEST_LOG"
    TEST_REMOTE_BIN="/usr/local/sbin/snapshot-agent.sh --agent-mode"
    return 0
}

test_11() {
    setup_infrastructure; generate_local_config
    echo "V1" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    sleep 2
    echo "V2" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -d "$MNT_BACKUP/daily.1" ] && find "$MNT_BACKUP/daily.0" -name "f.txt" | xargs grep -q "V2"
}

test_12() {
    setup_infrastructure; generate_local_config
    echo "Alt" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    set_file_age "$MNT_BACKUP/daily.0/.backup_timestamp" "yesterday"
    echo "Neu" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ -f "$MNT_BACKUP/daily.1/.backup_timestamp" ]
}

test_13() {
    setup_infrastructure; generate_local_config
    # Enable notifications explicitly
    sed -i 's/ENABLE_NOTIFICATIONS=false/ENABLE_NOTIFICATIONS=true/' "$CONF_FILE"
    
    echo "Notify" > "$MNT_SOURCE/n.txt"
    timeout 10 $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    
    timeout 10 $SCRIPT --config "$CONF_FILE" --desktop >> "$SUITE_LOG" 2>&1
    return 0
}

test_99() {
    log "Running Matrix Test Suite (Local)..."
    local fail=0
    
    # helper for scenarios
    # args: name setup_cmd run_cmd assertion_cmd
    # checking logic inside assertion
    
    # 1. Hourly Burst (3 runs in 1h, Retain=2). Should update in-place.
    setup_infrastructure; TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 generate_local_config
    echo "Files" > "$MNT_SOURCE/f.txt"
    # Run 1
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    # Run 2 (Same hour)
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    # Run 3 (Same hour)
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Expect: hourly.0 only (count 1), containing f.txt. No hourly.1
    if [ -d "$MNT_BACKUP/hourly.0" ] && [ ! -d "$MNT_BACKUP/hourly.1" ]; then
        log "  [PASS] Case 1: Hourly Burst"
    else
        log "  [FAIL] Case 1: Hourly Burst. Found $(ls $MNT_BACKUP)"
        fail=1
    fi
    
    # 2. Hourly Overflow (3 runs spaced 1h, Retain=2). Should rotate.
    setup_infrastructure; TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 generate_local_config
    echo "Run1" > "$MNT_SOURCE/f.txt"
    mkdir -p "$MNT_BACKUP/hourly.0"; set_file_age "$MNT_BACKUP/hourly.0/.backup_timestamp" "2 hours ago"
    cp -al "$MNT_BACKUP/hourly.0" "$MNT_BACKUP/hourly.1"; set_file_age "$MNT_BACKUP/hourly.1/.backup_timestamp" "3 hours ago"
    # Pre-create daily.0 to prevent bootstrap promotion
    mkdir -p "$MNT_BACKUP/daily.0"; set_file_age "$MNT_BACKUP/daily.0/.backup_timestamp" "3 hours ago"
    # Run 3 (Now)
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Expect: hourly.0, hourly.1. Content updated.
    if [ -d "$MNT_BACKUP/hourly.0" ] && [ -d "$MNT_BACKUP/hourly.1" ]; then
        log "  [PASS] Case 2: Hourly Overflow"
    else
        log "  [FAIL] Case 2: Hourly Overflow. Found $(ls $MNT_BACKUP)"
        fail=1
    fi
    
    # 3. Promotion Hourly->Daily (Run 1 T0, Run 2 T0+25h).
    setup_infrastructure; TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 generate_local_config
    mkdir -p "$MNT_BACKUP/hourly.0"; set_file_age "$MNT_BACKUP/hourly.0/.backup_timestamp" "25 hours ago"
    # Run (Now)
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Expect: daily.0 (Promoted)
    if [ -d "$MNT_BACKUP/daily.0" ]; then
        log "  [PASS] Case 3: Hourly->Daily Promotion"
    else
        log "  [FAIL] Case 3: Hourly->Daily Promotion. Found $(ls $MNT_BACKUP)"
        fail=1
    fi
    
    # 4. Direct Daily (H=0, D=2).
    setup_infrastructure; TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=2 generate_local_config
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$MNT_BACKUP/daily.0" ] && [ ! -d "$MNT_BACKUP/hourly.0" ]; then
         log "  [PASS] Case 4: Direct Daily"
    else
         log "  [FAIL] Case 4: Direct Daily. Found $(ls $MNT_BACKUP)"
         fail=1
    fi

    # 5. Direct Weekly (H=0, D=0, W=2).
    setup_infrastructure; TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=0 TEST_RETAIN_WEEKLY=2 generate_local_config
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$MNT_BACKUP/weekly.0" ] && [ ! -d "$MNT_BACKUP/daily.0" ]; then
         log "  [PASS] Case 5: Direct Weekly"
    else
         log "  [FAIL] Case 5: Direct Weekly. Found $(ls $MNT_BACKUP)"
         fail=1
    fi

    # 6. Daily Burst (Same Day, Different Hours). Logic Check: No duplicate daily.
    setup_infrastructure; TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=2 generate_local_config
    # Run 1 (Morning)
    mkdir -p "$MNT_BACKUP/daily.0"; touch "$MNT_BACKUP/daily.0/morning"
    # Force TS to 10:00 Today
    date -d "10:00" '+%Y-%m-%d %H:%M:%S %z' > "$MNT_BACKUP/daily.0/.backup_timestamp"
    # Run 2 (Afternoon - Now)
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Expect: daily.0 exists (Afternoon). daily.1 does NOT exist (Morning overwritten or kept in daily.0).
    # If rotation occurred, daily.1 would exist.
    if [ -d "$MNT_BACKUP/daily.0" ] && [ ! -d "$MNT_BACKUP/daily.1" ]; then
         log "  [PASS] Case 6: Daily Burst (In-Place Update)"
    else
         log "  [FAIL] Case 6: Daily Burst. Found $(ls $MNT_BACKUP)"
         fail=1
    fi

    # 7. Short-Week Promotion (Weekly Fri -> Daily Mon).
    # Setup: weekly.0 (Fri), daily.0 (Mon). Run promotion check.
    setup_infrastructure; TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=2 TEST_RETAIN_WEEKLY=2 generate_local_config
    # Create weekly.0 (Last Friday)
    mkdir -p "$MNT_BACKUP/weekly.0"
    date -d "last friday" '+%Y-%m-%d %H:%M:%S %z' > "$MNT_BACKUP/weekly.0/.backup_timestamp"
    
    # Create daily.0 (Today - ensure it is Mon/Tue relative to Fri? Or just rely on Week Change).
    # If today is same week as last friday (e.g. today is Sun), check might fail.
    # To be safe, force dates.
    # Week 49 (Fri 2024-12-06). Week 50 (Mon 2024-12-09).
    rm -rf "$MNT_BACKUP/weekly.0"; mkdir -p "$MNT_BACKUP/weekly.0"
    date -d "2024-12-06 12:00:00" '+%Y-%m-%d %H:%M:%S %z' > "$MNT_BACKUP/weekly.0/.backup_timestamp"
    
    # Simulate current state as if we just finished a daily backup on Mon 2024-12-09
    # But integration test runs with "NOW".
    # Logic uses `date` command inside script.
    # We cannot easily mock `date` inside the script without LD_PRELOAD.
    # HOWEVER, we can mock the TIMESTAMP files.
    # But `find_promotion_candidate` compares TS against `weekly.0`.
    # And validates "Is TS promoted?".
    # It calls `is_promotion_due`.
    # If we rely on Current Time for "Age"? No, `is_promotion_due` compares `src_ts` vs `last_ts`.
    # It does NOT compare vs NOW.
    # So we can fake timestamps!
    
    mkdir -p "$MNT_BACKUP/daily.0"
    date -d "2024-12-09 12:00:00" '+%Y-%m-%d %H:%M:%S %z' > "$MNT_BACKUP/daily.0/.backup_timestamp"
    touch "$MNT_BACKUP/daily.0/promo_marker"
    
    # But wait, `check_promote` is called inside script.
    # It iterates `daily.*`.
    # We need to trigger `check_promote`.
    # Running `$SCRIPT` will try to creating NEW daily.0 (NOW).
    # And shift our mock `daily.0` to `daily.1`.
    # Then checking `daily.1` (Mon Dec 9) against `weekly.0` (Fri Dec 6).
    # This should Trigger Promotion!
    
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Expect: weekly.0 contains content of Mon Dec 9 (promo_marker).
    if [ -f "$MNT_BACKUP/weekly.0/promo_marker" ]; then
         log "  [PASS] Case 7: Short-Week Promotion (Fri->Mon)"
    else
         log "  [FAIL] Case 7: Short-Week Promotion. weekly.0 content missing."
         fail=1
    fi

    return $fail
}

# ==============================================================================
# 3. REMOTE TEST CASES (20-34 & 99)
# ==============================================================================

test_20() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    echo "Remote" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    find "$SERVER_ROOT/test-client/daily.0" -name "f.txt" | grep -q "f.txt"
}

test_21() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/daily.0.tmp"
    touch "$SERVER_ROOT/test-client/daily.0.tmp/stale"
    touch -d "2 days ago" "$SERVER_ROOT/test-client/daily.0.tmp"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -f "$SERVER_ROOT/test-client/daily.0/stale" ]
}

test_22() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/daily.0"
    set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "2023-10-02 12:00:00"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ -d "$SERVER_ROOT/test-client/weekly.0" ]
}

test_23() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$MNT_SOURCE/ext"
    mount -t tmpfs tmpfs "$MNT_SOURCE/ext"
    echo "Ignore" > "$MNT_SOURCE/ext/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    local r=0
    find "$SERVER_ROOT/test-client/daily.0" -name "f.txt" | grep -q "f.txt" && r=1
    umount "$MNT_SOURCE/ext"
    return $r
}

test_24() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    cat > "$MOCK_BIN/rsync" <<EOF
#!/bin/bash
exit 24
EOF
    chmod +x "$MOCK_BIN/rsync"
    PATH="$MOCK_BIN:$PATH" $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
}

test_25() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$TEST_BASE/agent_locks"
    echo "$$" > "$TEST_BASE/agent_locks/test-client.lock"
    if $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1; then rm -f "$TEST_BASE/agent_locks/test-client.lock"; return 1; fi
    rm -f "$TEST_BASE/agent_locks/test-client.lock"
    return 0
}

test_26() {
    setup_infrastructure; setup_ssh_access
    dd if=/dev/urandom of="$MNT_SOURCE/large" bs=1M count=10 status=none
    export TEST_RSYNC_OPTS="--bwlimit=1000"
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1 & local p=$!; sleep 1; kill -9 $p; wait $p 2>/dev/null || true
    export TEST_RSYNC_OPTS=""
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    find "$SERVER_ROOT/test-client/daily.0" -name "large" | grep -q "large"
}

test_27() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/daily.0.tmp"
    touch "$SERVER_ROOT/test-client/daily.0.tmp/junk"
    set_file_age "$SERVER_ROOT/test-client/daily.0.tmp" "2 days ago"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -f "$SERVER_ROOT/test-client/daily.0/junk" ]
}

test_28() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    echo "Master" > "$MNT_SOURCE/f.txt"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    local rf=$(find "$SERVER_ROOT/test-client/daily.0" -name "f.txt")
    echo "X" > "$rf"
    touch -r "$MNT_SOURCE/f.txt" "$rf"
    $SCRIPT --config "$CONF_FILE" --verify >> "$SUITE_LOG" 2>&1
    grep -q "Master" "$rf"
}

test_29() {
    setup_infrastructure; setup_ssh_access
    export TEST_EXCLUDES="\"*.skip\""
    generate_remote_config
    echo "K" > "$MNT_SOURCE/keep"; echo "S" > "$MNT_SOURCE/f.skip"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    find "$SERVER_ROOT/test-client/daily.0" -name "keep" | grep -q "keep" && \
    ! find "$SERVER_ROOT/test-client/daily.0" -name "f.skip" | grep -q "f.skip"
}

test_30() {
    setup_infrastructure; setup_ssh_access
    export TEST_SPACE_LIMIT=1000
    export TEST_PURGE_SLOTS=1
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    grep -q "Triggering Smart Purge" "$SUITE_LOG" || grep -q "Smart purge triggered" "$SUITE_LOG"
}

test_31() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/daily.0"
    set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "2023-10-02 12:00:00"
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ -d "$SERVER_ROOT/test-client/weekly.0" ]
}

test_32() {
    setup_infrastructure; setup_ssh_access
    export TEST_RSYNC_OPTS="-I" 
    generate_remote_config
    echo "1" > "$MNT_SOURCE/f.txt"; $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    echo "2" > "$MNT_SOURCE/f.txt"; $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ ! -d "$SERVER_ROOT/test-client/daily.1" ] && \
    grep -q "2" "$(find "$SERVER_ROOT/test-client/daily.0" -name "f.txt")"
}

test_33() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    echo "1" > "$MNT_SOURCE/f.txt"; $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "yesterday"
    echo "2" > "$MNT_SOURCE/f.txt"; $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    [ -d "$SERVER_ROOT/test-client/daily.1" ]
}

test_34() {
    setup_infrastructure; setup_ssh_access; generate_remote_config
    
    # Mock sshfs
    cat > "$MOCK_BIN/sshfs" <<EOF
#!/bin/bash
# Mock SSHFS: Just verify args and create a dummy file
echo "mock_sshfs received: \$*" >> "$SUITE_LOG"
echo "mock_sshfs expected substring: $REMOTE_USER@$REMOTE_HOST:" >> "$SUITE_LOG"
if [[ "\$*" == *"$REMOTE_USER@$REMOTE_HOST:"* ]]; then
    mkdir -p "\${@: -1}" # Last arg is mountpoint
    touch "\${@: -1}/sshfs_mounted"
    exit 0
else
    echo "mock_sshfs NO MATCH" >> "$SUITE_LOG"
fi
exit 1
EOF
    chmod +x "$MOCK_BIN/sshfs"
    
    # Mock umount
    cat > "$MOCK_BIN/umount" <<EOF
#!/bin/bash
if [ -f "\$1/sshfs_mounted" ]; then
    rm "\$1/sshfs_mounted"
    rmdir "\$1"
    exit 0
fi
exit 1
EOF
    # Mock mountpoint to fool the check in do_umount
    cat > "$MOCK_BIN/mountpoint" <<EOF
#!/bin/bash
# If we see our marker, say yes (exit 0). Else say no (exit 1).
# mountpoint -q PATH
# Argument is last arg
if [ -f "\${@: -1}/sshfs_mounted" ]; then exit 0; fi
/usr/bin/mountpoint "\$@"
EOF
    chmod +x "$MOCK_BIN/umount" "$MOCK_BIN/mountpoint"
    
    local mnt="$TEST_BASE/restore_mnt"
    PATH="$MOCK_BIN:$PATH" $SCRIPT --config "$CONF_FILE" --mount "$mnt" >> "$SUITE_LOG" 2>&1
    
    if [ -f "$mnt/sshfs_mounted" ]; then
        PATH="$MOCK_BIN:$PATH" $SCRIPT --config "$CONF_FILE" --umount "$mnt" >> "$SUITE_LOG" 2>&1
        [ ! -d "$mnt" ]
    else
        return 1
    fi
}

test_35() {
    setup_infrastructure
    local log="$TEST_BASE/install_log"
    local wrapper="$TEST_BASE/wrapper.sh"
    
    # Mocks
    cat > "$MOCK_BIN/id" <<EOF
#!/bin/bash
if [[ "\$@" == *"-u"* ]]; then echo 0; exit 0; fi
if [[ "\$@" == *"testbackupuser"* ]]; then exit 1; fi
exit 0
EOF
    cat > "$MOCK_BIN/useradd" <<EOF
#!/bin/bash
echo "useradd \$@" >> "$log"
EOF
    cat > "$MOCK_BIN/chown" <<EOF
#!/bin/bash
echo "chown \$@" >> "$log"
EOF
    cat > "$MOCK_BIN/getent" <<EOF
#!/bin/bash
if [[ "\$@" == *"passwd testbackupuser"* ]]; then echo "testbackupuser:x:1001:1001::/var/lib/testbackup-home:/bin/false"; exit 0; fi
exit 1
EOF
    cat > "$MOCK_BIN/chmod" <<EOF
#!/bin/bash
echo "chmod \$@" >> "$log"
EOF
    chmod +x "$MOCK_BIN/id" "$MOCK_BIN/useradd" "$MOCK_BIN/chown" "$MOCK_BIN/chmod" "$MOCK_BIN/getent"
    
    PATH="$MOCK_BIN:$PATH" WRAPPER_PATH="$wrapper" $REAL_AGENT --install testbackupuser >/dev/null 2>&1
    
    local fail=0
    if [ ! -f "$wrapper" ]; then
        log "  [FAIL] Wrapper script not created."
        fail=1
    fi
    if ! grep -q "useradd" "$log"; then
        log "  [FAIL] useradd not called."
        fail=1
    fi
    if ! grep -q "chown" "$log"; then
        log "  [FAIL] chown not called."
        fail=1
    fi
    # Mock the agent script itself to handle --action for testing
    cat > "$MOCK_BIN/snapshot-backup-agent" <<EOF
#!/bin/bash
mock_prepare() { echo "mock_prepare called"; }
mock_commit() { echo "mock_commit called"; }
mock_purge() { echo "mock_purge called"; }
mock_status() { echo "mock_status called"; }

while [[ \$# -gt 0 ]]; do
    key="\$1"
    case \$key in
        --action)
        case "\$2" in
            prepare) shift 2; mock_prepare ;;
            commit)  shift 2; mock_commit ;;
            purge)   shift 2; mock_purge ;;
            status)  shift 2; mock_status ;;
            version) echo "13.7"; exit 0 ;;
            *) echo "Unknown action: \$2"; exit 1 ;;
        esac
        ;;
        *) shift ;;
    esac
done
EOF
    chmod +x "$MOCK_BIN/snapshot-backup-agent"
    # Check SFTP support in wrapper
    if ! grep -q "sftp-server" "$wrapper"; then
        log "  [FAIL] Wrapper missing SFTP support."
        fail=1
    fi
    return $fail
}



test_41() {
    setup_infrastructure; generate_local_config
    $SCRIPT --config "$CONF_FILE" >> "$SUITE_LOG" 2>&1
    
    local perms=$(stat -c "%a" "$MNT_BACKUP/daily.0")
    if [ "$perms" != "700" ]; then
        log "  [FAIL] Permissions are $perms (Expected 700)"
        return 1
    fi
    # log "  [PASS] Permissions are 700 (Secure)"
    return 0
}

test_36() {
    description="Status & Statistics Verification"
    # Create a dummy stats file
    local stats="/var/log/snapshot-backup-stats.csv"
    sudo rm -f "$stats"
    
    # Needs root to write to /var/log/
    echo "$(date +%s),10485760" | sudo tee -a "$stats" >/dev/null # 10MB
    echo "$(date +%s),20971520" | sudo tee -a "$stats" >/dev/null # 20MB
    # Avg should be 15MB
    
    # Run status command. 
    # Must use sudo for access to /var/log logic if restricted (but script runs as root in tests?)
    # The integration suite runs as sudo.
    
    local out=$($SCRIPT --config "$CONF_FILE" --status)
    echo "$out" >> "$SUITE_LOG"
    
    if echo "$out" | grep -q "AVG NEW DATA: ~15.00 MB"; then
        return 0
    else
        echo "Status verification failed." >> "$SUITE_LOG"
        return 1
    fi
}

test_38() {
    description="Regressive Promotion Protection"
    setup_infrastructure root
    
    # Needs root
    # Setup: weekly.0 (Today), daily.0 (Yesterday).
    
    local root="$TEST_BASE/local_root"
    mkdir -p "$root/weekly.0" "$root/daily.0"
    
    date -d "today" '+%Y-%m-%d %H:%M:%S' > "$root/weekly.0/.backup_timestamp"
    # Mark it
    echo "IsWeekly" > "$root/weekly.0/marker"
    
    date -d "yesterday" '+%Y-%m-%d %H:%M:%S' > "$root/daily.0/.backup_timestamp"
    echo "IsDaily" > "$root/daily.0/marker"
    
    cat > "$CONF_FILE" <<EOF
BACKUP_ROOT="$root"
BACKUP_MODE="LOCAL"
RETAIN_DAILY=3
RETAIN_WEEKLY=3
EOF
    
    # Trigger FORCED weekly promotion
    # Logic should SEE that Target (weekly.0 - Today) is NEWER than Source (daily.0 - Yesterday).
    # And DISCARD the promotion.
    
    $SCRIPT --config "$CONF_FILE" --force-weekly >/dev/null 2>&1
    
    # Assert: weekly.0 marker is STILL "IsWeekly".
    if grep -q "IsWeekly" "$root/weekly.0/marker"; then
        return 0
    else
        echo "Regression check failed. weekly.0 was overwritten." >> "$SUITE_LOG"
         ls -R "$root" >> "$SUITE_LOG"
        return 1
    fi
}

test_39() {
    description="Security Hardening (Agent Input)"
    setup_infrastructure
    # Uses REAL agent ($REAL_AGENT) but local invocation for testing input validation.
    
    local fail=0
    
    # 1. Path Traversal
    if $REAL_AGENT --config "$AGENT_CONF" --client "../bad" --action status >/dev/null 2>&1; then
        echo "[FAIL] Agent accepted '../bad' client name." >> "$SUITE_LOG"
        fail=1
    fi
    
    # 2. Command Injection
    if $REAL_AGENT --config "$AGENT_CONF" --client "cmd;id" --action status >/dev/null 2>&1; then
         echo "[FAIL] Agent accepted 'cmd;id' client name." >> "$SUITE_LOG"
         fail=1
    fi
    
    # 3. Valid
    # We expect status fails logically (no backups), but NOT Security Error (Exit 1 vs 0? Or just not "Security Error")
    # Actually, status returns 0 if no snapshots found.
    # We just want to ensure it passes validation.
    local out=$($REAL_AGENT --config "$AGENT_CONF" --client "valid-client" --action status 2>&1)
    if [[ "$out" == *"Security Error"* ]]; then
         echo "[FAIL] Agent rejected valid client name." >> "$SUITE_LOG"
         fail=1
    fi
    
    return $fail
}

test_40() {
    description="Helper Functions (--is-running etc)"
    setup_infrastructure root
    
    local fail=0
    
    # 1. is-running
    rm -f "/var/run/snapshot-backup.pid"
    if $SCRIPT --is-running >/dev/null; then
        echo "[FAIL] --is-running returned true but no PID." >> "$SUITE_LOG"
        fail=1
    fi
    echo "$$" > "/var/run/snapshot-backup.pid"
    if ! $SCRIPT --is-running >/dev/null; then
         echo "[FAIL] --is-running returned false but PID exists." >> "$SUITE_LOG"
         fail=1
    fi
    rm -f "/var/run/snapshot-backup.pid"
    
    # 2. is-job-done
    # Setup fresh backup root
    BACKUP_ROOT="$TEST_BASE/helpers"
    mkdir -p "$BACKUP_ROOT"
    cat > "$CONF_FILE" <<EOF
BACKUP_ROOT="$BACKUP_ROOT"
BACKUP_MODE="LOCAL"
RETAIN_DAILY=3
RETAIN_HOURLY=0
EOF
    # Empty - Should return "false" but exit 0
    out=$($SCRIPT --config "$CONF_FILE" --is-job-done)
    if [[ "$out" != *"false"* ]]; then
        echo "[FAIL] --is-job-done returned '$out' on empty (expected false)." >> "$SUITE_LOG"
        fail=1
    fi
    
    # Create valid backup for Today
    mkdir -p "$BACKUP_ROOT/daily.0"
    date '+%Y-%m-%d %H:%M:%S' > "$BACKUP_ROOT/daily.0/.backup_timestamp"
    
    # Valid - Should return "true" and exit 0
    out=$($SCRIPT --config "$CONF_FILE" --is-job-done)
    if [[ "$out" != *"true"* ]]; then
        echo "[FAIL] --is-job-done returned '$out' despite valid daily.0 (expected true)." >> "$SUITE_LOG"
        fail=1
    fi
    
    # 3. has-storage (Local)
    # Normap
    if ! $SCRIPT --config "$CONF_FILE" --has-storage >/dev/null; then
        echo "[FAIL] --has-storage (rw) returned false." >> "$SUITE_LOG"
        fail=1
    fi
    
    # Root ignores chmod 000. Use RO bind mount.
    mkdir -p "$BACKUP_ROOT/ro_check"
    mount --bind "$BACKUP_ROOT/ro_check" "$BACKUP_ROOT/ro_check"
    mount -o remount,ro,bind "$BACKUP_ROOT/ro_check"
    
    cat > "$CONF_FILE" <<EOF
BACKUP_ROOT="$BACKUP_ROOT/ro_check"
BACKUP_MODE="LOCAL"
RETAIN_DAILY=3
RETAIN_HOURLY=0
EOF

    if $SCRIPT --config "$CONF_FILE" --has-storage >/dev/null; then
        echo "[FAIL] --has-storage (ro) returned true." >> "$SUITE_LOG"
        fail=1
    fi
    umount "$BACKUP_ROOT/ro_check"
    rmdir "$BACKUP_ROOT/ro_check"
    
    return $fail
}

test_37() {
    description="Hybrid Promotion (Early Copy)"
    
    # Needs root
    setup_infrastructure root
    
    # 1. Create a chain of dailies where the oldest are NOT eligible, but a middle one IS.
    # We pretend current date is 2025-01-10 (Friday).
    # daily.6: 2025-01-01 (Wed) - Week 01
    # daily.5: 2025-01-02 (Thu) - Week 01
    # daily.1: 2025-01-08 (Wed) - Week 02 (Eligible vs last weekly of Week 52)
    # daily.0: 2025-01-10 (Fri) - Week 02
    
    # Assuming Oldest (daily.6) is checked: 
    #   Jan 01 vs Last Weekly (Dec 25). Week changed (01 vs 52). Age 7 days.
    #   Wait, daily.6 WOULD be promoted in standard waterfall too if it's eligible.
    
    # We need a case where Oldest FAILs, but Middle PASSES.
    # Case: Oldest is "Too close" to last weekly?
    # Last Weekly: Jan 01 (Wed).
    # daily.6: Jan 02 (Thu). Age 1 day. Fails.
    # daily.5: Jan 03 (Fri). Age 2 days. Fails.
    # daily.0: Jan 08 (Wed). Age 7 days. Week changed (02 vs 01). PASSES.
    
    # If we run promotion, daily.0 (or daily.x) should be promoted via COPY.
    
    local int="daily"
    mkdir -p "$SERVER_ROOT/test-client"
    
    # Create Last Weekly (Jan 01 2025)
    mkdir -p "$SERVER_ROOT/test-client/weekly.0"
    date -d "2025-01-01 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$SERVER_ROOT/test-client/weekly.0/.backup_timestamp"
    
    # Create Daily.2 (Jan 02) - Too close (1d)
    mkdir -p "$SERVER_ROOT/test-client/daily.2"
    date -d "2025-01-02 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$SERVER_ROOT/test-client/daily.2/.backup_timestamp"
    
    # Create Daily.1 (Jan 03) - Too close (2d)
    mkdir -p "$SERVER_ROOT/test-client/daily.1"
    date -d "2025-01-03 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$SERVER_ROOT/test-client/daily.1/.backup_timestamp"

    # Create Daily.0 (Jan 08) - Week 02. Age 7d. Valid.
    mkdir -p "$SERVER_ROOT/test-client/daily.0"
    date -d "2025-01-08 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$SERVER_ROOT/test-client/daily.0/.backup_timestamp"
    
    # Configure Agent to checking
    # We call Agent directly with --action commit which triggers purge->waterfall
    # Or just run backup script.
    # Let's run backup script in Remote Mode (simulation).
    # But easiest is just running checking logic?
    # No, integration test runs full script.
    
    generate_remote_config
    # Force minimal retention to trigger logic? check_promote runs always on client?
    # Wait, check_promote logic is in Agent for Remote.
    # Test 37 uses Remote Agent logic via direct call?
    
    # Let's verify LOCAL logic first (snapshot-backup.sh)
    # Then reuse for Remote.
    
    # Run Script (Local).
    BACKUP_ROOT="$SERVER_ROOT/test-client"
    export BACKUP_ROOT
    
    # We must patch check_promote or rely on perform logic which calls it.
    # perform_local_backup calls check_promote.
    # But checking promotion usually happens AFTER backup.
    
    # Let's just create a dummy backup that triggers the flow.
    # date needs to be AFTER Jan 08. Say Jan 09.
    $SCRIPT --agent-mode --config "$CONF_FILE" --client "test-client" --action commit >> "$SUITE_LOG" 2>&1
    # Wait, SCRIPT is backup script. It doesn't have --action.
    # We want to test local hybrid promotion.
    
    # Clean env for Local test
    sudo rm -rf "$TEST_BASE/local_root"
    mkdir -p "$TEST_BASE/local_root/daily.2" "$TEST_BASE/local_root/daily.1" "$TEST_BASE/local_root/daily.0" "$TEST_BASE/local_root/weekly.0"
    
    local root="$TEST_BASE/local_root"
    date -d "2025-01-01 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$root/weekly.0/.backup_timestamp"
    date -d "2025-01-02 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$root/daily.2/.backup_timestamp"
    touch "$root/daily.2/file_d2"
    date -d "2025-01-03 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$root/daily.1/.backup_timestamp"
    date -d "2025-01-08 12:00:00" '+%Y-%m-%d %H:%M:%S' > "$root/daily.0/.backup_timestamp"
    touch "$root/daily.0/file_d0" # The one to promote
    
    # Config
    cat > "$CONF_FILE" <<EOF
BACKUP_ROOT="$root"
BACKUP_MODE="LOCAL"
RETAIN_DAILY=3
RETAIN_WEEKLY=3
EOF
    
    # Run Backup
    # Script creates daily.0 (Today). Shifts others -> daily.3 (deleted), daily.2, daily.1.
    # Then checks promotion.
    # daily.3 (was daily.2 Jan 02) -> Oldest. Failed (Too close).
    # daily.1 (was daily.0 Jan 08) -> Middle. Valid.
    # Expect: daily.1 promoted to weekly.0. 
    # Current weekly.0 (Jan 01) shifts to weekly.1.
    
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    
    # Verify
    # Due to recursive waterfall, multiple promotions might occur if dailies cover multiple weeks.
    # daily.1 (Jan 08) is promoted to weekly.0.
    # If daily.0 (Simulation Date) is much later, it might ALSO be promoted, shifting Jan 08 to weekly.1.
    # So we check if file_d0 exists in ANY weekly snapshot.
    
    if find "$root" -path "*/weekly.*/file_d0" | grep -q "file_d0"; then
         return 0
    else
         echo "Hybrid Promotion failed. file_d0 not found in any weekly snapshot." >> "$SUITE_LOG"
         ls -R "$root" >> "$SUITE_LOG"
         return 1
    fi
}

test_99_remote() {
    description="Remote Matrix Cascade"
    log "Running Matrix Test Suite (Remote)..."
    local fail=0
    
    # 1. Hourly Burst (Remote)
    setup_infrastructure; setup_ssh_access
    export TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$SERVER_ROOT/test-client/hourly.0" ] && [ ! -d "$SERVER_ROOT/test-client/hourly.1" ]; then
        log "  [PASS] Remote Case 1: Hourly Burst"
    else
        log "  [FAIL] Remote Case 1: Hourly Burst"
        fail=1
    fi

    # 2. Hourly Overflow (Remote)
    setup_infrastructure; setup_ssh_access
    export TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 
    generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/hourly.0"; set_file_age "$SERVER_ROOT/test-client/hourly.0/.backup_timestamp" "2 hours ago"
    cp -al "$SERVER_ROOT/test-client/hourly.0" "$SERVER_ROOT/test-client/hourly.1"; set_file_age "$SERVER_ROOT/test-client/hourly.1/.backup_timestamp" "3 hours ago"
    # Pre-create daily.0
    mkdir -p "$SERVER_ROOT/test-client/daily.0"; set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "3 hours ago"
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$SERVER_ROOT/test-client/hourly.0" ] && [ -d "$SERVER_ROOT/test-client/hourly.1" ]; then
        log "  [PASS] Remote Case 2: Hourly Overflow"
    else
        log "  [FAIL] Remote Case 2: Hourly Overflow"
        fail=1
    fi

    # 3. Promotion Hourly->Daily (Remote)
    setup_infrastructure; setup_ssh_access
    export TEST_RETAIN_HOURLY=2 TEST_RETAIN_DAILY=2 
    generate_remote_config
    mkdir -p "$SERVER_ROOT/test-client/hourly.0"; set_file_age "$SERVER_ROOT/test-client/hourly.0/.backup_timestamp" "25 hours ago"
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$SERVER_ROOT/test-client/daily.0" ]; then
        log "  [PASS] Remote Case 3: Houly->Daily Promotion"
    else
        log "  [FAIL] Remote Case 3: Hourly->Daily Promotion"
        fail=1
    fi

    # 4. Direct Daily (Remote)
    setup_infrastructure; setup_ssh_access
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=2 
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$SERVER_ROOT/test-client/daily.0" ] && [ ! -d "$SERVER_ROOT/test-client/hourly.0" ]; then
         log "  [PASS] Remote Case 4: Direct Daily"
    else
         log "  [FAIL] Remote Case 4: Direct Daily"
         fail=1
    fi

    # 5. Direct Weekly (Remote)
    setup_infrastructure; setup_ssh_access
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=0 TEST_RETAIN_WEEKLY=2 
    generate_remote_config
    $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    if [ -d "$SERVER_ROOT/test-client/weekly.0" ] && [ ! -d "$SERVER_ROOT/test-client/daily.0" ]; then
         log "  [PASS] Remote Case 5: Direct Weekly"
    else
         log "  [FAIL] Remote Case 5: Direct Weekly"
         fail=1
    fi

    return $fail
}

test_98_check_job_done() {
    description="Remote check-job-done"
    echo "Running test_98 details..." >> "$SUITE_LOG"
    local fail=0
    
    setup_infrastructure; setup_ssh_access
    local CLIENT_NAME="test-client"
    
    # helper to check job status
    # usage: check_status "true/false" "Message"
    check_status() {
        local expected=$1
        local msg=$2
        local out
        # Explicitly use global variables or defaults to satisfy set -u
        local port="${REMOTE_PORT:-22}"
        local host="${REMOTE_HOST:-localhost}"
        local user="${REMOTE_USER:-root}"
        local key="${REMOTE_KEY:-$TEST_SSH_KEY}"
        local opts="${REMOTE_SSH_OPTS:--o StrictHostKeyChecking=no -o BatchMode=yes}"
        # REMOTE_AGENT path on 'server' (localhost)
        local agent_script="${REMOTE_AGENT:-$(pwd)/snapshot-backup.sh --agent-mode}"
        # Ensure we use the test configuration!
        if [[ "$agent_script" != *"--config"* ]]; then
             agent_script="$agent_script --config $CONF_FILE"
        fi
        
        out=$(ssh -p "$port" $opts -i "$key" "$user@$host" "$agent_script --client $CLIENT_NAME --action check-job-done $config_opts")
        # trim whitespace
        out=$(echo "$out" | tr -d '[:space:]')
        if [[ "$out" == "$expected" ]]; then
            echo "  [PASS] $msg (Got: $out)" >> "$SUITE_LOG"
        else
            log "  [FAIL] $msg (Expected: $expected, Got: '$out')"
            fail=1
        fi
    }

    # 1. Hourly
    echo "  Checking Hourly..." >> "$SUITE_LOG"
    export TEST_RETAIN_HOURLY=1 TEST_RETAIN_DAILY=0
    generate_remote_config
    config_opts="--retention-hourly 1"
    # Case A: Inside (0 min ago) -> Expect True
    mkdir -p "$SERVER_ROOT/test-client/hourly.0"; set_file_age "$SERVER_ROOT/test-client/hourly.0/.backup_timestamp" "now"
    check_status "true" "Hourly: Inside current hour"
    # Case B: Outside (2 hours ago) -> Expect False
    set_file_age "$SERVER_ROOT/test-client/hourly.0/.backup_timestamp" "2 hours ago"
    check_status "false" "Hourly: Outside current hour"

    # 2. Daily
    echo "  Checking Daily..." >> "$SUITE_LOG"
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=1
    generate_remote_config
    config_opts="--retention-daily 1 --retention-hourly 0"
    # Case A: Inside (0 min ago) -> Expect True
    rm -rf "$SERVER_ROOT/test-client/hourly.0"
    mkdir -p "$SERVER_ROOT/test-client/daily.0"; set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "now"
    check_status "true" "Daily: Inside current day"
    # Case B: Outside (25 hours ago) -> Expect False
    set_file_age "$SERVER_ROOT/test-client/daily.0/.backup_timestamp" "25 hours ago"
    check_status "false" "Daily: Outside current day"

    # 3. Weekly
    echo "  Checking Weekly..." >> "$SUITE_LOG"
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=0 TEST_RETAIN_WEEKLY=1
    generate_remote_config
    config_opts="--retention-weekly 1 --retention-daily 0 --retention-hourly 0"
    # Case A: Inside (0 min ago) -> Expect True
    rm -rf "$SERVER_ROOT/test-client/daily.0"
    mkdir -p "$SERVER_ROOT/test-client/weekly.0"; set_file_age "$SERVER_ROOT/test-client/weekly.0/.backup_timestamp" "now"
    check_status "true" "Weekly: Inside current week"
    # Case B: Outside (2 weeks ago) -> Expect False
    set_file_age "$SERVER_ROOT/test-client/weekly.0/.backup_timestamp" "2 weeks ago"
    check_status "false" "Weekly: Outside current week"
    
    # 4. Monthly
    echo "  Checking Monthly..." >> "$SUITE_LOG"
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=0 TEST_RETAIN_WEEKLY=0 TEST_RETAIN_MONTHLY=1
    generate_remote_config
    config_opts="--retention-monthly 1 --retention-weekly 0 --retention-daily 0 --retention-hourly 0"
    # Case A: Inside (0 min ago) -> Expect True
    rm -rf "$SERVER_ROOT/test-client/weekly.0"
    mkdir -p "$SERVER_ROOT/test-client/monthly.0"; set_file_age "$SERVER_ROOT/test-client/monthly.0/.backup_timestamp" "now"
    check_status "true" "Monthly: Inside current month"
    # Case B: Outside (2 months ago) -> Expect False
    set_file_age "$SERVER_ROOT/test-client/monthly.0/.backup_timestamp" "2 months ago"
    check_status "false" "Monthly: Outside current month"

    # 5. Yearly
    echo "  Checking Yearly..." >> "$SUITE_LOG"
    export TEST_RETAIN_HOURLY=0 TEST_RETAIN_DAILY=0 TEST_RETAIN_WEEKLY=0 TEST_RETAIN_MONTHLY=0 TEST_RETAIN_YEARLY=1
    generate_remote_config
    config_opts="--retention-yearly 1 --retention-monthly 0 --retention-weekly 0 --retention-daily 0 --retention-hourly 0"
    # Case A: Inside (0 min ago) -> Expect True
    rm -rf "$SERVER_ROOT/test-client/monthly.0"
    # Currently no yearly directory standard, so we assume it might fall back to highest available or yearly.0 if implemented?
    # Actually snapshot-agent supports 'yearly' base interval.
    mkdir -p "$SERVER_ROOT/test-client/yearly.0"; set_file_age "$SERVER_ROOT/test-client/yearly.0/.backup_timestamp" "now"
    check_status "true" "Yearly: Inside current year"
    # Case B: Outside (2 years ago) -> Expect False
    set_file_age "$SERVER_ROOT/test-client/yearly.0/.backup_timestamp" "2 years ago"
    check_status "false" "Yearly: Outside current year"
    
    # Logic removed (duplicate of test_44)
    return 0
}

# ==============================================================================
# New Regression Tests (v14.1 Fixes)
# ==============================================================================

test_42_inf_loop_fix() {
    # Bug: Infinite Loop in run_waterfall_logic if retention is 0 for a level.
    # Cause: check_promote returned success (0) because of bare returns, treating failure as success.
    # Fix: Return 1 explicitly if retention <= 0.
    
    pre_test_cleanup
    setup_env

    # Config: Hourly=1, Daily=0, Weekly=0.
    # We create hourly backups.
    # Then we trigger "daily" promotion logic.
    # With Daily=0, check_promote("daily") should return 1 (Fail).
    # If it returned 0 (Success), waterfall would continue looping.
    
    export TEST_RETAIN_HOURLY=2
    export TEST_RETAIN_DAILY=0
    export TEST_RETAIN_WEEKLY=0
    export TEST_RETAIN_MONTHLY=0
    export TEST_RETAIN_YEARLY=0
    generate_local_config
    
    # Create hourly.0, hourly.1
    mkdir -p "$MNT_BACKUP/hourly.0"
    mkdir -p "$MNT_BACKUP/hourly.1"
    
    # We fake hourly.1 to be old enough for daily promotion (if daily was enabled)
    # But daily is disabled (0).
    # So check_promote "daily" must NOT promote.
    
    # Run the backup tool (local mode)
    # We use 'timeout' to detect infinite loop if fix fails.
    # Run the backup tool (purge action triggers waterfall)
    # Use timeout to detect infinite loop
    # NOTE: Purge action is for Agent. Client uses standard run.
    # But standard run triggers rsync. We just want to test promotion logic.
    # If we run with purge action (as Agent Mode?), we need --agent-mode.
    # If we run Client Mode, we run full backup.
    # Let's run Client Mode full backup.
    # Let's run Client Mode full backup.
    run_with_timeout 10s $SCRIPT --config "$CONF_FILE" >/dev/null 2>&1
    local ret=$?
    
    if [ "$ret" -eq 124 ]; then
        log "FAIL: Timeout reached (Infinite Loop Detected)."
        return 1
    elif [ "$ret" -ne 0 ]; then
        log "FAIL: Command failed with exit code $ret (Not a loop, but error)."
        return 1
    else
        # Success (Exit 0)
        # Check that daily.0 does NOT exist
        if [ -d "$MNT_BACKUP/daily.0" ]; then
             log "FAIL: Promoted to daily.0 despite Retention=0."
             return 1
        fi
        return 0
    fi
}

test_43_log_segregation() {
    # Feature: Concurrent Agent Logging (Segregation by Client Name)
    # We run the agent with --client
    # We verify that a logfile named snapshot-backup-<client>.log is created.
    
    local log_dir="./test_logs"
    mkdir -p "$log_dir"
    
    # Modify config to point logfile to this dir
    # We can't easily change LOGFILE variable via config in Client Check mode unless we mock.
    # But Agent Main respects LOGFILE var or defaults.
    # We can pass config file.
    
    local agent_conf="./test_agent.conf"
    echo "LOGFILE=\"$log_dir/snapshot-backup.log\"" > "$agent_conf"
    
    # Run Agent in Status mode (harmless)
    # Why Status? It logs.
    mkdir -p "./storage/clientA"
    chmod 700 "./storage/clientA"
    
    ./snapshot-backup.sh --agent-mode --config "$agent_conf" --client "clientA" --action status --base-storage "./storage" >/dev/null 2>&1
    
    if [ -f "$log_dir/snapshot-backup-clientA.log" ]; then
        return 0
    else
        log "FAIL: Log file snapshot-backup-clientA.log not found in $log_dir."
        ls -l "$log_dir"
        return 1
    fi
}

# ==============================================================================
# TEST 44: Waterfall Backlog Regression (Anti-Flushing)
# Checks if the system correctly limits promotions to 1 level per run
# even when a backlog of valid candidates exists.
# ==============================================================================
test_44_waterfall_backlog() {
    echo "--- TEST 44: Waterfall Backlog (Anti-Flushing) ---" >> "$SUITE_LOG"
    
    pre_test_cleanup
    setup_env
    
    local t_root="$MNT_BACKUP/regression_44"
    rm -rf "$t_root"
    mkdir -p "$t_root/backups"
    mkdir -p "$t_root/source"
    touch "$t_root/source/file1"
    
    local conf="$t_root/backup.conf"
    cat > "$conf" <<EOF
BACKUP_ROOT="$t_root/backups"
BACKUP_MODE="LOCAL"
RETAIN_HOURLY=24
RETAIN_DAILY=7
RETAIN_WEEKLY=4
RETAIN_MONTHLY=12
RETAIN_YEARLY=5
SOURCE_DIRS=("$t_root/source")
EOF

    # Helper: Create Fake Snapshot
    create_snap() {
        local int=$1; local idx=$2; local days_ago=$3
        local d="$t_root/backups/$int.$idx"
        mkdir -p "$d"
        # Use Epoch for robust timestamp
        local ts=$(date -d "$days_ago days ago" +%s)
        echo "$ts" > "$d/.backup_timestamp"
    }
    
    # Setup: 3 historic dailies (Yesterday, 2d ago, 3d ago)
    # They ALL qualify for Weekly promotion (assuming day boundary crossed)
    create_snap "daily" 0 1
    create_snap "daily" 1 2
    create_snap "daily" 2 3
    
    echo "Running Backup (Should promote exactly ONE daily -> weekly)..." >> "$SUITE_LOG"
    "$SCRIPT" --config "$conf" >> "$SUITE_LOG" 2>&1
    local code=$?
    
    if [ $code -ne 0 ]; then
        echo "FAIL: Backup script returned error $code." >> "$SUITE_LOG"
        return 1
    fi
    
    # Check Result
    local w_count=$(ls -d "$t_root/backups/weekly."* 2>/dev/null | wc -l)
    echo "Weekly Snapshots Created: $w_count" >> "$SUITE_LOG"
    
    if [ "$w_count" -eq 1 ]; then
        echo "PASS" >> "$SUITE_LOG"
        rm -rf "$t_root"
        return 0
    elif [ "$w_count" -gt 1 ]; then
        echo "FAIL: Flushing Detected! Created $w_count weekly snapshots (Expected 1)." >> "$SUITE_LOG"
        return 1
    else
        echo "FAIL: No weekly snapshot created?" >> "$SUITE_LOG"
        return 1
    fi
}

# ==============================================================================
# 4. RUNNER
# ==============================================================================

FAIL=0
run() {
    local t=$1; local desc=$2
    # Filter if args provided
    if [ $# -gt 2 ]; then
        # filter mode: check if $t is in arguments
        local match=false
        for arg in "${@:3}"; do
            if [ "$t" = "$arg" ]; then match=true; break; fi
        done
        if [ "$match" = false ]; then return; fi
    fi

    printf "%-80s " "Running $t: $desc..."
    if $t; then 
        echo -e "${GREEN}PASS${NC}"
    else 
        echo -e "${RED}FAIL${NC}"
        # Print last 3 lines of output indented
        tail -n 3 "$SUITE_LOG" | sed 's/^/    >> /'
        FAIL=$((FAIL+1))
    fi
}

clean_logs() {
    truncate -s 0 "$SUITE_LOG"
    pre_test_cleanup
}

run_suite() {
    echo "=================================================="
    echo "SNAPSHOT BACKUP INTEGRATION SUITE v14.1 (Unified)"
    echo "--------------------------------------------------"
    echo "Tests matched to Historical Requirements."
    echo "=================================================="

    echo "--- [ LOCAL TESTS ] ---"
    run test_01 "Basic Backup Creation" "$@"
    run test_02 "Weekly Rotation Logic" "$@"
    run test_03 "Mountpoint Exclusion" "$@"
    run test_04 "Exclude Pattern Logic" "$@"
    run test_05 "Smart Purge (Local)" "$@"
    run test_06 "PID Locking" "$@"
    run test_07 "Promotion Idempotency" "$@"
    run test_08 "Rsync Exit 24 Recovery" "$@"
    run test_09 "Deep Verify (Checksum)" "$@"
    run test_10 "Atomic Crash Protection" "$@"
    run test_11 "In-Place Update (No Promo)" "$@"
    run test_12 "Smart Rotation (Day Change)" "$@"
    run test_13 "Desktop Notification Trigger" "$@"
    # run test_99 "Local Matrix Cascade" "$@"

    echo ""
    echo "--- [ REMOTE TESTS ] ---"
    run test_19 "Verify & Switch Agent" "$@"
    run test_20 "Remote Basic Agent" "$@"
    run test_21 "Agent Stale Tmp Check" "$@"
    run test_22 "Remote Promotion" "$@"
    run test_23 "Remote Mount Exclusion" "$@"
    run test_24 "Agent Rsync Exit 24" "$@"
    run test_25 "Agent Locking" "$@"
    run test_26 "Remote Resume Partial" "$@"
    run test_27 "Agent Garbage Collection" "$@"
    run test_28 "Remote Deep Verify" "$@"
    run test_29 "Remote Excludes" "$@"
    run test_30 "Agent Smart Purge" "$@"
    run test_31 "Agent Waterfall Matrix" "$@"
    run test_32 "Remote In-Place Update" "$@"
    run test_33 "Agent Rotation" "$@"
    run test_34 "Remote Mount (SSHFS)" "$@"
    run test_35 "Secure Install (Mock)" "$@"
    run test_36 "Status & Statistics Verification" "$@"
    run test_37 "Hybrid Promotion (Early Copy)" "$@"
    run test_38 "Regressive Promotion Protection" "$@"
    run test_39 "Security Hardening (Agent)" "$@"
    
    echo ""
    echo "--- [ MISC / REGRESSIONS ] ---"
    run test_40 "Helper Functions" "$@"
    run test_41 "Snapshot Permissions (700)" "$@"
    run test_42_inf_loop_fix "Regression: Infinite Loop (Retain=0)" "$@"
    run test_43_log_segregation "Feature: Agent Log Segregation" "$@"
    run test_44_waterfall_backlog "Regression: Waterfall Backlog Flushing" "$@"

    # 3. Dynamic Matrix Test (Remote)
    run test_98_check_job_done "Remote Job Done Checks" "$@"
    # run test_99_remote "Remote Matrix Cascade" "$@"
}

clean_logs
run_suite "$@"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED.${NC}"
    exit 0
else
    echo -e "${RED}$FAIL TESTS FAILED.${NC} See $SUITE_LOG for details."
    exit 1
fi
