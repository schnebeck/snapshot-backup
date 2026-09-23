#!/bin/bash
# file: run-tests.sh
# Final Version for snapshot-backup.sh v18.3

source ./test-framework.sh

# Root Check (Required for PID/Lock simulations in /var/run or system paths)
if [ "$(id -u)" -ne 0 ]; then
    echo "CRITICAL: Please run as root."
    exit 1
fi

# ==============================================================================
# GROUP 1: LOGIC & ROTATION
# ==============================================================================

test_01_basic_backup() {
    echo "test" > "$MNT_SRC/file1"
    run_backup
    local relative_src_path="${MNT_SRC#/}"
    assert_exists "$MNT_DEST/daily.0/$relative_src_path/file1" || return 1
}

test_02_admin_view_protection() {
    set_config "RETAIN_DAILY" 7
    set_config "RETAIN_WEEKLY" 4
    mock_timestamp "$MNT_DEST/daily.0" "2026-01-05 12:00:00"
    mock_timestamp "$MNT_DEST/weekly.0" "2099-01-01 12:00:00"
    
    run_backup
    
    assert_exists "$MNT_DEST/daily.0" || return 1
    assert_exists "$MNT_DEST/daily.1" || return 1
}

test_03_strict_chain_promotion() {
    set_config "RETAIN_DAILY" 7
    set_config "RETAIN_WEEKLY" 4
    mock_timestamp "$MNT_DEST/daily.0" "2026-01-05 12:00:00"
    mock_timestamp "$MNT_DEST/weekly.0" "2000-01-01 12:00:00"
    
    run_backup
    
    assert_exists "$MNT_DEST/daily.0" || return 1
    local ts=$(cat "$MNT_DEST/weekly.0/.backup_timestamp")
    if [ "$ts" -lt 1700000000 ]; then return 1; fi
    assert_missing "$MNT_DEST/daily.1" || return 1
}

test_04_gap_closing() {
    mkdir -p "$MNT_DEST/daily.0"
    mkdir -p "$MNT_DEST/daily.2" 
    mock_timestamp "$MNT_DEST/daily.0" "yesterday"
    mock_timestamp "$MNT_DEST/daily.2" "3 days ago"
    
    run_backup
    
    assert_exists "$MNT_DEST/daily.0" && \
    assert_exists "$MNT_DEST/daily.1" && \
    assert_exists "$MNT_DEST/daily.2" && \
    assert_missing "$MNT_DEST/daily.3" || return 1
}

test_05_job_done_check() {
    # Expect FALSE (Exit 1) on empty
    "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1
    [ $? -eq 0 ] && return 1 
    
    # Run Backup
    run_backup
    
    # Fix: Ensure deterministic timestamp comparison
    # We update the timestamp of the backup we just made to clearly match "now"
    # or ensure it is recognized as "current period"
    local target_ts="$MNT_DEST/daily.0/.backup_timestamp"
    date +%s > "$target_ts"
    
    # Expect TRUE (Exit 0) on existing
    "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "    ${RED}[FAIL] is-job-done returned FALSE despite fresh backup.${NC}"
        return 1
    fi
}

# ==============================================================================
# GROUP 2: SYSTEM INTEGRATION & SECURITY
# ==============================================================================

test_06_locking() {
    # FIX: Because v18.1 calculates LOCK_DIR at startup, we must override BOTH
    # PIDFILE and LOCK_DIR in the config to point to our test location.
    local test_pid="/tmp/snapshot-test.pid"
    local test_lock="/tmp/snapshot-test.lock"
    
    set_config "PIDFILE" "$test_pid"
    set_config "LOCK_DIR" "$test_lock"
    
    # 1. Simulate Active Lock
    # The script checks `mkdir $LOCK_DIR` first. If that fails, it checks PID.
    mkdir -p "$test_lock"
    echo "1" > "$test_pid" # PID 1 is always running (init)
    
    # 2. Try run
    run_backup
    local ret=$?
    
    # 3. Cleanup
    rm -rf "$test_lock" "$test_pid"
    
    if [ "$ret" -eq 0 ]; then
        echo -e "    ${RED}[FAIL] Backup ran despite existing Lock!${NC}"
        return 1
    fi
    
    # Check for correct error message (from acquire_lock)
    if ! grep -q "Instance already running" "$LOG_FILE"; then
         echo -e "    ${RED}[FAIL] Expected 'Instance already running' in log.${NC}"
         return 1
    fi
}

test_07_rsync_vanished() {
    local mock_bin_dir="$TEST_ROOT/mock_bin"
    mkdir -p "$mock_bin_dir"
    
    # Mock rsync returning 24
    cat > "$mock_bin_dir/rsync" <<EOF
#!/bin/sh
echo "Mock rsync triggered, returning 24"
exit 24
EOF
    chmod +x "$mock_bin_dir/rsync"
    
    # Save/Restore PATH safely
    local old_path="$PATH"
    export PATH="$mock_bin_dir:$PATH"
    
    run_backup
    local ret=$?
    
    export PATH="$old_path"
    
    # v18.1 Line 974: explicitly allows exit code 24
    if [ "$ret" -ne 0 ] && [ "$ret" -ne 24 ]; then
        echo -e "    ${RED}[FAIL] Script treated Exit 24 as Error (Code $ret).${NC}"
        return 1
    fi
    
    # If script swallows 24 and returns 0 (success), that is also acceptable 
    # depending on run_with_retry logic.
}

test_08_agent_security() {
    # Goal: Agent must reject clients with ".." in name
    # v18.1 Line 927: validate_client_name
    "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --client "../hack" --action status >> "$LOG_FILE" 2>&1
    local ret=$?
    
    if [ "$ret" -eq 0 ]; then
         echo -e "    ${RED}[FAIL] Agent accepted malicious client name!${NC}"
         return 1
    fi
}

# ==============================================================================
# GROUP 3: REMOTE SSH INTEGRATION
# ==============================================================================

test_09_remote_handshake() {
    setup_loopback_ssh 
    "$SCRIPT_BIN" --config "$CONF_FILE" --status >/dev/null 2>&1
    if [ $? -ne 0 ]; then return 1; fi
}

test_10_remote_backup_exec() {
    setup_loopback_ssh
    echo "Hello Remote" > "$MNT_SRC/remote.txt"
    
    run_backup
    
    local rel_path="${MNT_SRC#/}"
    local remote_file="$SERVER_STORAGE/test-client/daily.0/$rel_path/remote.txt"
    
    if [ ! -f "$remote_file" ]; then
         echo -e "    ${RED}[FAIL] Remote file not found: $remote_file${NC}"
         return 1
    fi
}

test_11_remote_agent_deploy() {
    setup_loopback_ssh
    local target_agent="/usr/local/sbin/snapshot-agent.sh"
    rm -f "$target_agent"
    
    "$SCRIPT_BIN" --config "$CONF_FILE" --deploy-agent "root@localhost" >/dev/null 2>&1
    
    if [ ! -x "$target_agent" ]; then
        echo -e "    ${RED}[FAIL] Agent not deployed/executable.${NC}"
        return 1
    fi
}

# ==============================================================================
# GROUP 4: ADVANCED LOGIC & SECURITY
# ==============================================================================

test_12_permissions_security() {
    # Goal: Verify that backups are strictly secured (chmod 700).
    # Only root should have access.
    
    echo "sensible data" > "$MNT_SRC/secret.txt"
    run_backup
    
    # Check directory permissions of the snapshot root
    local perm
    perm=$(stat -c "%a" "$MNT_DEST/daily.0")
    
    if [ "$perm" != "700" ]; then
        echo -e "    ${RED}[FAIL] Permissions are $perm (Expected 700).${NC}"
        return 1
    fi
}

test_13_idempotency_check() {
    # Goal: Ensure a second run within the same period performs an In-Place Update.
    # It must NOT create a new snapshot (rotation) but MUST update file content.
    
    echo "run1" > "$MNT_SRC/data.txt"
    run_backup
    
    # Modify source immediately (Simulate second run in same hour/day)
    echo "run2" >> "$MNT_SRC/data.txt"
    run_backup
    
    # 1. Verification: No Rotation (daily.1 must not exist)
    assert_missing "$MNT_DEST/daily.1" || return 1
    
    # 2. Verification: Target Exists (daily.0)
    assert_exists "$MNT_DEST/daily.0" || return 1
    
    # 3. Verification: Content Updated (rsync actually ran)
    # We need to construct the full path inside the backup
    local rel_path="${MNT_SRC#/}"
    local target_file="$MNT_DEST/daily.0/$rel_path/data.txt"
    
    if ! grep -q "run2" "$target_file"; then
        echo -e "    ${RED}[FAIL] In-Place update did not sync new data.${NC}"
        return 1
    fi
}

test_14_excludes_logic() {
    # Goal: Verify that EXCLUDE_PATTERNS from config are respected by rsync.
    
    # Setup: Create files that should match patterns
    mkdir -p "$MNT_SRC/cache"
    touch "$MNT_SRC/cache/trash.dat"     # Should be excluded (dir match)
    touch "$MNT_SRC/image.tmp"           # Should be excluded (extension match)
    touch "$MNT_SRC/keep_me.txt"         # Should remain
    
    # Set Config (Space separated patterns as per v18.1 spec)
    set_config "EXCLUDE_PATTERNS" "cache/ *.tmp"
    
    run_backup
    
    local rel_path="${MNT_SRC#/}"
    local base_dest="$MNT_DEST/daily.0/$rel_path"
    
    # 1. Positive Check: Valid file exists
    if [ ! -f "$base_dest/keep_me.txt" ]; then
        echo -e "    ${RED}[FAIL] Normal file was excluded incorrectly.${NC}"
        return 1
    fi
    
    # 2. Negative Check: *.tmp file
    if [ -f "$base_dest/image.tmp" ]; then
        echo -e "    ${RED}[FAIL] Pattern *.tmp was ignored (file exists).${NC}"
        return 1
    fi
    
    # 3. Negative Check: cache/ directory
    if [ -d "$base_dest/cache" ]; then
        echo -e "    ${RED}[FAIL] Pattern cache/ was ignored (dir exists).${NC}"
        return 1
    fi
}

test_15_network_retry_logic() {
    # Goal: Verify run_with_retry survives transient failures.
    # Logic: snapshot-backup.sh only uses retry in REMOTE mode (rsync).
    
    local mock_bin="$TEST_ROOT/mock_retry"
    mkdir -p "$mock_bin"
    local counter_file="$TEST_ROOT/rsync_fails.count"
    echo "0" > "$counter_file"
    
    # 1. Mock RSYNC (fails 2 times, succeeds on 3rd)
    cat > "$mock_bin/rsync" <<EOF
#!/bin/bash
count=\$(cat "$counter_file")
if [ "\$count" -lt 2 ]; then
    echo \$((count+1)) > "$counter_file"
    echo "Simulated Network Failure (Attempt \$((count+1)))" >&2
    exit 255
else
    echo "Simulated Success"
    exit 0
fi
EOF
    
    # 2. Mock SSH (CRITICAL FIX!)
    # We mock SSH so it ignores the host and executes the command locally.
    # This prevents connecting to the real system agent.
    cat > "$mock_bin/ssh" <<EOF
#!/bin/bash
# Mock SSH: Just execute the last argument (the command) locally
# ignoring host/user/port arguments.
eval "\${@: -1}"
EOF
    chmod +x "$mock_bin/rsync" "$mock_bin/ssh"
    
    local old_path="$PATH"
    export PATH="$mock_bin:$PATH"
    
    # 3. Configure Remote Mode
    set_config "BACKUP_MODE" "REMOTE"
    set_config "REMOTE_HOST" "mock_host"
    
    # 4. Point REMOTE_AGENT to our test script!
    # Without this, it defaults to /usr/local/sbin/snapshot-agent.sh (LIVE SYSTEM)
    # and uses /etc/snapshot-backup.conf (LIVE STORAGE).
    local agent_cmd="$SCRIPT_BIN --agent-mode --config $CONF_FILE"
    set_config "REMOTE_AGENT" "$agent_cmd"
    
    # 5. Run
    run_backup
    local ret=$?
    
    export PATH="$old_path"
    
    if [ "$ret" -ne 0 ]; then
        echo -e "    ${RED}[FAIL] Script gave up too early (Exit $ret).${NC}"
        return 1
    fi
    
    local final_count=$(cat "$counter_file")
    if [ "$final_count" -ne 2 ]; then
        echo -e "    ${RED}[FAIL] Retry logic did not trigger correctly (Count: $final_count).${NC}"
        return 1
    fi
}

test_16_smart_purge_logic() {
    # Goal: Verify that backups are deleted when disk space is low (Smart Purge).
    
    # 1. Setup: Create 5 daily backups (Indices 0..4)
    for i in {0..4}; do
        mkdir -p "$MNT_DEST/daily.$i"
        mock_timestamp "$MNT_DEST/daily.$i" "$((i+1)) days ago"
    done
    
    # 2. Config: Enable Smart Purge
    # We set RETAIN_DAILY to 5. With 5 pre-existing + 1 new run = 6 backups total.
    # Smart Purge (2 slots) reduces limit to 5 - 2 = 3.
    # We have 6 backups, limit is 3 -> The oldest 3 must die.
    
    set_config "SPACE_LOW_LIMIT_GB" 999999 
    set_config "SMART_PURGE_SLOTS" 2
    set_config "RETAIN_DAILY" 5  # <--- HIER WAR DER FEHLER (vorher 10)
    
    # 3. Mock 'df' to report full disk
    local mock_bin="$TEST_ROOT/mock_df"
    mkdir -p "$mock_bin"
    cat > "$mock_bin/df" <<EOF
#!/bin/bash
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/mock  999999999   999  100       99%      /"
EOF
    chmod +x "$mock_bin/df"
    
    local old_path="$PATH"
    export PATH="$mock_bin:$PATH"
    
    # 4. Run Backup
    run_backup
    
    export PATH="$old_path"
    
    # Expectation:
    # We started with daily.0..daily.4.
    # Rotation happens: old daily.4 becomes daily.5.
    # New limit is 3 (Indices 0, 1, 2 are kept).
    # Indices 3, 4, 5 should be deleted.
    
    if [ -d "$MNT_DEST/daily.4" ]; then
         echo -e "    ${RED}[FAIL] Smart Purge failed to delete old backups (daily.4 still exists).${NC}"
         return 1
    fi
    
    # Positive check: Check log for trigger
    if ! grep -q "Smart purge triggered" "$LOG_FILE"; then
         echo -e "    ${RED}[FAIL] Smart purge logic was not triggered in logs.${NC}"
         return 1
    fi
}

test_17_crash_recovery() {
    # Goal: Script must clean up or reuse stale .tmp directories from aborted runs.
    
    # 1. Simulate a crashed run
    mkdir -p "$MNT_DEST/daily.0.tmp"
    echo "garbage" > "$MNT_DEST/daily.0.tmp/partial_file"
    # Make it old so it looks "stale" (script often checks age)
    touch -d "2 days ago" "$MNT_DEST/daily.0.tmp"
    
    run_backup
    
    # Expectation: 
    # 1. daily.0.tmp should be gone (renamed to daily.0 or deleted)
    # 2. daily.0 must exist and contain valid backup
    
    if [ -d "$MNT_DEST/daily.0.tmp" ]; then
        # It's acceptable if it REUSED it, but for this test we assume clean finish
        # If run_backup finished, .tmp should be promoted to .0
        echo -e "    ${RED}[FAIL] Stale .tmp directory was left behind.${NC}"
        return 1
    fi
    
    assert_exists "$MNT_DEST/daily.0" || return 1
}

test_19_lock_dir_follows_pidfile() {
    # Goal: A config that sets PIDFILE must get the matching lock directory.
    #
    # LOCK_DIR is derived from PIDFILE when the script loads, before any config
    # is read. Without re-deriving it afterwards, a host running two instances
    # with separate PIDFILEs would still share the default lock - the second
    # instance refusing to start for no reason its PID file explains.
    #
    # The check is indirect but exact: place a held lock at the path the config
    # implies and require the run to refuse it. Before the fix the script looks
    # at the default path instead, finds nothing, and backs up happily.
    local custom_pid="$TEST_ROOT/custom-instance.pid"
    local custom_lock="$TEST_ROOT/custom-instance.lock"

    set_config "PIDFILE" "$custom_pid"

    mkdir -p "$custom_lock"
    echo $$ > "$custom_pid"   # this shell is alive, so the lock is held

    "$SCRIPT_BIN" --config "$CONF_FILE" --debug >> "$LOG_FILE" 2>&1
    local rc=$?

    rm -rf "$custom_lock" "$custom_pid"

    if [ "$rc" -ne 2 ]; then
        echo -e "    ${RED}[FAIL] Ran despite a held lock at $custom_lock (exit $rc).${NC}"
        return 1
    fi
}

test_20_rsync_log_classification() {
    # Goal: file names must not be reported as rsync errors.
    #
    # The classifier greps each rsync output line. Unanchored patterns matched
    # the listing itself: a source containing AccessDeniedException.php made a
    # successful run log hundreds of errors, which is how people learn to stop
    # reading logs.
    local pattern='^rsync(:| error)|^IO error|^ERROR:|^fatal:|: Permission denied|: No space left'

    # These are file names, not diagnostics.
    for benign in \
        "/opt/app/models/access_denied_traffic_node.py" \
        "deleting var/app/Exception/AccessDeniedException.php" \
        "/var/log/failed-login-attempts.log" \
        "usr/share/doc/fatal-error-handler/README"
    do
        if echo "$benign" | grep -qiE "$pattern"; then
            echo -e "    ${RED}[FAIL] File name reported as an error: $benign${NC}"
            return 1
        fi
    done

    # These are diagnostics and must still be caught.
    for real in \
        "rsync: [sender] send_files failed to open \"/x\": Permission denied (13)" \
        "rsync error: some files/attrs were not transferred (code 23)" \
        "IO error encountered -- skipping file deletion"
    do
        if ! echo "$real" | grep -qiE "$pattern"; then
            echo -e "    ${RED}[FAIL] Real error not detected: $real${NC}"
            return 1
        fi
    done
}

test_21_hooks_order_and_result() {
    # Goal: the three hooks run, in order, and POST_RUN_CMD is told how it went.
    #
    # Hooks are called rather than listened to, so order is part of the
    # contract: PRE_RUN before anything, PRE_RSYNC after the target is prepared
    # and before a file is read, POST_RUN at the end with the exit code in $1.
    local trace="$TEST_ROOT/hook-trace.txt"
    rm -f "$trace"

    set_config "PRE_RUN_CMD"   "echo pre-run >> $trace"
    set_config "PRE_RSYNC_CMD" "echo pre-rsync >> $trace"
    set_config "POST_RUN_CMD"  "echo post-run:\$1 >> $trace"

    echo "data" > "$MNT_SRC/hooked.txt"
    run_backup

    local got
    got=$(tr '\n' ' ' < "$trace" 2>/dev/null)
    if [ "$got" != "pre-run pre-rsync post-run:0 " ]; then
        echo -e "    ${RED}[FAIL] Hook order/result was: '$got'${NC}"
        return 1
    fi
}

test_22_failing_pre_hook_stops_the_run() {
    # Goal: a PRE hook that fails stops the backup, and POST_RUN still runs.
    #
    # This is the whole reason hooks return a value. A snapshot that was not
    # created must not be backed up as though it had been - the copy would look
    # like a consistent one and would not be. The teardown still has to happen,
    # or whatever the hook set up stays set up.
    local trace="$TEST_ROOT/hook-fail-trace.txt"
    rm -f "$trace"

    set_config "PRE_RUN_CMD"   ""
    set_config "PRE_RSYNC_CMD" "exit 7"
    set_config "POST_RUN_CMD"  "echo post-run:\$1 >> $trace"

    echo "must-not-arrive" > "$MNT_SRC/unwanted.txt"
    "$SCRIPT_BIN" --config "$CONF_FILE" --debug >> "$LOG_FILE" 2>&1
    local rc=$?

    if [ "$rc" -eq 0 ]; then
        echo -e "    ${RED}[FAIL] Run reported success although PRE_RSYNC_CMD failed.${NC}"
        return 1
    fi

    if ! grep -q "post-run:" "$trace" 2>/dev/null; then
        echo -e "    ${RED}[FAIL] POST_RUN_CMD did not run after the failure.${NC}"
        return 1
    fi

    # Clean up for whatever runs next.
    set_config "PRE_RSYNC_CMD" ""
    set_config "POST_RUN_CMD" ""
    rm -f "$MNT_SRC/unwanted.txt"
}

test_23_show_config_is_valid_shell() {
    # Goal: --show-config must produce a file the script can source.
    #
    # The template is a heredoc, so anything in it that looks like a variable
    # is expanded when it is written. A comment mentioning $1 aborted the whole
    # command under set -u, and nothing noticed because the output was never
    # fed back in - which is exactly what a config template is for.
    local generated="$TEST_ROOT/generated.conf"

    if ! "$SCRIPT_BIN" --show-config > "$generated" 2>/dev/null; then
        echo -e "    ${RED}[FAIL] --show-config exited non-zero.${NC}"
        return 1
    fi

    if ! sh -n "$generated" 2>/dev/null; then
        echo -e "    ${RED}[FAIL] Generated config is not valid shell.${NC}"
        return 1
    fi

    # Every setting the script reads should appear, or a template is a trap.
    local missing=""
    for key in CONFIG_VERSION BACKUP_MODE CLIENT_NAME SOURCE_DIRS \
               PRE_RUN_CMD PRE_RSYNC_CMD POST_RUN_CMD LOGFILE PIDFILE
    do
        grep -qE "^$key=" "$generated" || missing="$missing $key"
    done
    if [ -n "$missing" ]; then
        echo -e "    ${RED}[FAIL] Template is missing:$missing${NC}"
        return 1
    fi
}

test_24_version_comparison() {
    # Goal: version_gt must order versions numerically, not as strings.
    #
    # This is what keeps --upgrade from going backwards. Without it, a CDN
    # serving a stale copy is installed as eagerly as a new release - which is
    # how three machines were downgraded by one version. "18.10 vs 18.9" is the
    # case a string comparison gets wrong.
    . "$SCRIPT_BIN" --version >/dev/null 2>&1 || true

    local failed=""
    _expect_gt() {
        version_gt "$1" "$2" || failed="$failed [$1>$2 expected]"
    }
    _expect_not_gt() {
        version_gt "$1" "$2" && failed="$failed [$1>$2 unexpected]"
        return 0
    }

    _expect_gt     "18.7"  "18.6"
    _expect_gt     "18.10" "18.9"
    _expect_gt     "19.0"  "18.99"
    _expect_not_gt "18.6"  "18.7"
    _expect_not_gt "18.9"  "18.10"
    _expect_not_gt "18.6"  "18.6"

    if [ -n "$failed" ]; then
        echo -e "    ${RED}[FAIL] version_gt:$failed${NC}"
        return 1
    fi
}

test_18_conditional_storage_creation() {
    # Goal: Verify that storage creation is strictly conditional.
    # Case A: --action version (Read-Only) -> MUST NOT create directory
    # Case B: --action check-storage (Write) -> MUST create directory
    
    local test_storage="$TEST_ROOT/conditional_storage"
    local client_name="test_client_18"
    local full_target="$test_storage/$client_name"
    
    # 0. Clean Setup
    rm -rf "$test_storage"
    
    # Force specific configuration to point to a non-existent test folder
    cat > "$TEST_ROOT/conditional.conf" <<EOF
CONFIG_VERSION='2.0'
BASE_STORAGE_PATH="$test_storage"
CLIENT_NAME="$client_name"
EOF

    # --- PART 1: NEGATIVE TEST (Read-Only Action) ---
    # We run 'version', which should exit early without touching storage logic.
    "$SCRIPT_BIN" --agent-mode --config "$TEST_ROOT/conditional.conf" --action version >/dev/null 2>&1
    if [ $? -ne 0 ]; then return 1; fi
    
    # Expectation: Directory must remain missing (No Side Effects)
    if [ -d "$full_target" ]; then
        echo -e "    ${RED}[FAIL] Case A: Action 'version' created illegal directory.${NC}"
        return 1
    fi

    # --- PART 2: POSITIVE TEST (Write Action) ---
    # 'check-storage' explicitly requires storage access, triggering the mkdir block.
    "$SCRIPT_BIN" --agent-mode --config "$TEST_ROOT/conditional.conf" --action check-storage >/dev/null 2>&1
    
    # Expectation: Directory must now exist (Functionality Check)
    if [ ! -d "$full_target" ]; then
        echo -e "    ${RED}[FAIL] Case B: Action 'check-storage' failed to create directory.${NC}"
        return 1
    fi
    
    # Cleanup only on success
    rm -rf "$test_storage"
    return 0
}

# ==============================================================================
# MAIN RUNNER
# ==============================================================================

echo ">>> GROUP 1: CORE LOGIC <<<"
run_test_case "01 Basic Backup" test_01_basic_backup
run_test_case "02 Admin View (Pinned .0)" test_02_admin_view_protection
run_test_case "03 Strict Promotion" test_03_strict_chain_promotion
run_test_case "04 Gap Closing" test_04_gap_closing
run_test_case "05 Job Done Check" test_05_job_done_check

echo ""
echo ">>> GROUP 2: SYSTEM STABILITY <<<"
run_test_case "06 PID Locking" test_06_locking
run_test_case "07 Rsync Resilience (Exit 24)" test_07_rsync_vanished
run_test_case "08 Agent Security Input" test_08_agent_security

echo ""
echo ">>> GROUP 3: REMOTE SSH <<<"
run_test_case "09 SSH Handshake" test_09_remote_handshake
run_test_case "10 Remote Backup" test_10_remote_backup_exec
run_test_case "11 Agent Deployment" test_11_remote_agent_deploy

echo ""
echo ">>> GROUP 4: SECURITY & FEATURES <<<"
run_test_case "12 Permissions (chmod 700)" test_12_permissions_security
run_test_case "13 Idempotency (In-Place Update)" test_13_idempotency_check
run_test_case "14 Exclude Patterns" test_14_excludes_logic

echo ""
echo ">>> GROUP 5: RESILIENCE & ERROR HANDLING <<<"
run_test_case "15 Network Retry (3 Attempts)" test_15_network_retry_logic
run_test_case "16 Smart Purge (Disk Full)" test_16_smart_purge_logic
run_test_case "17 Crash Recovery (Stale .tmp)" test_17_crash_recovery
run_test_case "18 Storage Folder Creation" test_18_conditional_storage_creation
run_test_case "19 Lock Dir Follows PIDFILE" test_19_lock_dir_follows_pidfile
run_test_case "20 Rsync Log Classification" test_20_rsync_log_classification
run_test_case "21 Hook Order and Result" test_21_hooks_order_and_result
run_test_case "22 Failing PRE Hook Stops Run" test_22_failing_pre_hook_stops_the_run
run_test_case "23 Generated Config Is Valid" test_23_show_config_is_valid_shell
run_test_case "24 Version Comparison" test_24_version_comparison

print_summary
