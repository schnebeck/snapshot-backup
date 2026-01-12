#!/bin/bash
# file: test-framework.sh
# Framework library for snapshot-backup.sh v18.1+
# Added: Argument Filtering & Persistent Logging

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Paths
TEST_ROOT="/tmp/backup-tests"
MNT_SRC="$TEST_ROOT/source"
MNT_DEST="$TEST_ROOT/backup"
SERVER_STORAGE="$TEST_ROOT/server_storage"
CONF_FILE="$TEST_ROOT/test.conf"
# FIX: Logfile is now fixed in /tmp so you can tail -f it easily
LOG_FILE="/tmp/snapshot-test-suite.log" 
SCRIPT_BIN="$(pwd)/snapshot-backup.sh"

# SSH Specifics
TEST_SSH_KEY="$TEST_ROOT/id_ed25519_test"
AUTH_KEYS="$HOME/.ssh/authorized_keys"
KNOWN_HOSTS="$HOME/.ssh/known_hosts"

# Global Counters
TESTS_RUN=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Filter Argument (passed from runner)
TEST_FILTER="$1"

# --- Setup & Teardown ---

init_test_env() {
    [ -d "$TEST_ROOT" ] && rm -rf "$TEST_ROOT"
    mkdir -p "$MNT_SRC" "$MNT_DEST" "$SERVER_STORAGE"
    
    cat > "$CONF_FILE" <<EOF
CONFIG_VERSION="2.0"
BACKUP_MODE="LOCAL"
BACKUP_ROOT="$MNT_DEST"
SOURCE_DIRS="$MNT_SRC"
RETAIN_HOURLY=0
RETAIN_DAILY=7
RETAIN_WEEKLY=4
RETAIN_MONTHLY=12
RETAIN_YEARLY=2
LOGFILE="$LOG_FILE"
ENABLE_NOTIFICATIONS=false
SPACE_LOW_LIMIT_GB=0
SMART_PURGE_SLOTS=0
EOF
    # Separator in Logfile
    echo "==================================================================" >> "$LOG_FILE"
    echo "INIT TEST ENV: $(date)" >> "$LOG_FILE"
    echo "==================================================================" >> "$LOG_FILE"
}

setup_loopback_ssh() {
    ssh-keygen -t ed25519 -f "$TEST_SSH_KEY" -N "" -q
    mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
    cat "$TEST_SSH_KEY.pub" >> "$AUTH_KEYS"; chmod 600 "$AUTH_KEYS"
    ssh-keyscan -p 22 -t ed25519 localhost >> "$KNOWN_HOSTS" 2>/dev/null
    ssh-keyscan -p 22 -t ed25519 127.0.0.1 >> "$KNOWN_HOSTS" 2>/dev/null
    
    local agent_cmd="$SCRIPT_BIN --agent-mode --config $CONF_FILE"
    set_config "BACKUP_MODE" "REMOTE"
    set_config "REMOTE_HOST" "localhost"
    set_config "REMOTE_USER" "$(whoami)"
    set_config "REMOTE_PORT" "22"
    set_config "SSH_KEY" "$TEST_SSH_KEY"
    set_config "REMOTE_AGENT" "$agent_cmd"
    set_config "CLIENT_NAME" "test-client"
    set_config "REMOTE_STORAGE_ROOT" "$SERVER_STORAGE"
    echo "BASE_STORAGE=\"$SERVER_STORAGE\"" >> "$CONF_FILE"
}

mock_timestamp() {
    local path="$1"
    local date_str="$2" 
    if [ ! -e "$path" ]; then mkdir -p "$path"; fi
    date -d "$date_str" +%s > "$path/.backup_timestamp"
    touch -d "$date_str" "$path"
}

set_config() {
    local key="$1"
    local val="$2"
    sed -i "/^$key=/d" "$CONF_FILE"
    echo "$key=\"$val\"" >> "$CONF_FILE"
}

run_backup() {
    echo "CMD START: snapshot-backup.sh --config $CONF_FILE" >> "$LOG_FILE"
    # Capture both streams to logfile
    "$SCRIPT_BIN" --config "$CONF_FILE" --debug >> "$LOG_FILE" 2>&1
    local ret=$?
    echo "CMD END: Exit Code $ret" >> "$LOG_FILE"
    return $ret
}

assert_exists() {
    if [ ! -e "$1" ]; then
        echo -e "    ${RED}[FAIL] Expected: $1 to exist.${NC}"
        TESTS_FAILED=$((TESTS_FAILED+1))
        return 1
    fi
}

assert_missing() {
    if [ -e "$1" ]; then
        echo -e "    ${RED}[FAIL] Expected: $1 to be missing.${NC}"
        TESTS_FAILED=$((TESTS_FAILED+1))
        return 1
    fi
}

# In test-framework.sh suchen und ersetzen:

run_test_case() {
    local name="$1"
    local func="$2"
    
    # FILTER LOGIC 
    if [ -n "$TEST_FILTER" ]; then
        if [[ "$name" != *"$TEST_FILTER"* ]] && [[ "$func" != *"$TEST_FILTER"* ]]; then
            return 0
        fi
    fi

    printf "%-60s" "Test: $name..."
    TESTS_RUN=$((TESTS_RUN+1))
    
    init_test_env
    
    if $func; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED+1))
        echo "    --- LAST LOG LINES ($LOG_FILE) ---"
        tail -n 5 "$LOG_FILE" | sed 's/^/    >> /'
    fi
}

print_summary() {
    echo "------------------------------------------------"
    echo "Tests Run: $TESTS_RUN | Failures: $TESTS_FAILED"
    if [ "$TESTS_RUN" -eq 0 ]; then
        echo -e "${YELLOW}No tests matched filter '$TEST_FILTER'${NC}"
        exit 0
    fi
    [ "$TESTS_FAILED" -eq 0 ] && echo -e "${GREEN}ALL GREEN.${NC}" && exit 0
    echo -e "${RED}ERRORS FOUND.${NC}" && exit 1
}

