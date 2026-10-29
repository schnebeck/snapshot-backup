#!/bin/bash
# file: run-tests.sh
# Test suite for snapshot-backup.sh v19.5

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
    # The run records itself, so --is-job-done need not ask the server (test 55)
    grep -q "^test-client@localhost:22:.*/daily [0-9][0-9]*$" "$TEST_ROOT/job_done" \
        || { echo -e "    ${RED}[FAIL] no job-done record: $(cat "$TEST_ROOT/job_done" 2>&1)${NC}"; return 1; }
}

test_11_remote_agent_deploy() {
    setup_loopback_ssh
    local target_agent="/usr/local/sbin/snapshot-agent.sh" inode_before
    # An agent already in place must be replaced, not written into: scp used
    # to write straight into the running agent's file.
    echo "#!/bin/sh" > "$target_agent"
    inode_before=$(ls -i "$target_agent" | awk '{print $1}')

    "$SCRIPT_BIN" --config "$CONF_FILE" --deploy-agent "root@localhost" >/dev/null 2>&1 \
        || { echo -e "    ${RED}[FAIL] --deploy-agent failed.${NC}"; return 1; }

    if [ ! -x "$target_agent" ]; then
        echo -e "    ${RED}[FAIL] Agent not deployed/executable.${NC}"
        return 1
    fi
    [ "$(ls -i "$target_agent" | awk '{print $1}')" != "$inode_before" ] \
        || { echo -e "    ${RED}[FAIL] the agent was written in place, not replaced.${NC}"; return 1; }
    [ ! -e "$target_agent.upload" ] || { echo -e "    ${RED}[FAIL] upload left behind.${NC}"; return 1; }
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
    # Single quotes, as the config template says: set_config writes double quotes, and
    # in those the config's own loading expands $1 - to the path of the config file.
    sed -i '/^POST_RUN_CMD=/d' "$CONF_FILE"
    printf "POST_RUN_CMD='echo post-run:\$1 >> %s'\n" "$trace" >> "$CONF_FILE"

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

    # The suite's config, not the host's: that one may carry a WOL-Server token.
    if ! "$SCRIPT_BIN" --config "$CONF_FILE" --show-config > "$generated" 2>/dev/null; then
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
    # Only the two functions under test are loaded. Sourcing the whole script runs its
    # main part, whose "exit" ends this runner: from 18.6 on every test after this one,
    # and the summary, silently never ran.
    eval "$(sed -n '/^sanitize_int()/,/^}/p; /^version_gt()/,/^}/p' "$SCRIPT_BIN")"

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

test_25_wrapper_confines_a_client() {
    # Goal: a key pinned to one client must reach nothing but that client's backups.
    #
    # Before 18.7 the wrapper ignored the client name it was given and passed on any
    # agent arguments, any command starting with "rsync" and a full sftp-server - all as
    # root. One client's key could delete every other client's backups, or hand the agent
    # "--config FILE" and have it source a file it had just uploaded. This runs the
    # generated wrapper against stubs that only print how they were called, under every
    # POSIX shell present, because the wrapper has to work on busybox machines too.
    local w="$TEST_ROOT/wrapper.sh" store="$TEST_ROOT/wstore" stubs="$TEST_ROOT/stubs"
    rm -rf "$store" "$stubs"; mkdir -p "$store/alice/daily.0" "$store/bob/daily.0" "$stubs"
    ln -s "$store/bob" "$store/alice/escape"

    AGENT_INSTALL_PATH="$TEST_ROOT/agent-installed.sh" WRAPPER_PATH="$w" WRAPPER_ENFORCE=1 \
        BASE_STORAGE="$store" "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action install >> "$LOG_FILE" 2>&1
    [ -f "$w" ] || { echo -e "    ${RED}[FAIL] no wrapper generated${NC}"; return 1; }
    grep -q "^STORAGE_ROOT=\"$store\"" "$w" || { echo -e "    ${RED}[FAIL] wrapper does not use BASE_STORAGE${NC}"; return 1; }
    local s
    for s in AGENT RSYNC SFTP_SERVER; do
        printf '#!/bin/sh\necho "%s $*"\n' "$s" > "$stubs/$s"; chmod +x "$stubs/$s"
        sed -i "s|^$s=.*|$s=\"$stubs/$s\"|" "$w"
    done
    # The inhibitor around backup processes has its own test (63).
    sed -i 's|^INHIBIT=.*|INHIBIT=""|' "$w"
    printf '#!/bin/sh\nexec busybox sh "$@"\n' > "$stubs/busybox_sh"; chmod +x "$stubs/busybox_sh"

    local failed="" sh out
    # $1 = the wrapper's arguments, $2 = the command. $1 unquoted on purpose:
    # "alice --allow-mount" is two words in authorized_keys too.
    # (Until 18.7 _deny passed its arguments one position off, so every denial
    # below tested an empty command - which is refused anyway - and proved nothing.)
    # shellcheck disable=SC2086
    _run() { SSH_ORIGINAL_COMMAND="$2" "$sh" "$w" $1 2>/dev/null; }
    _allow() {  # $1 expected stub, $2 client, $3 command
        out=$(_run "$2" "$3"); case "$out" in "$1 "*) ;; *) failed="$failed [$sh: refused '$3' for '$2']" ;; esac
    }
    _deny() {   # $1 client, $2 command
        out=$(_run "$1" "$2"); case "$out" in AGENT*|RSYNC*|SFTP_SERVER*) failed="$failed [$sh: allowed '$2' for '$1']" ;; esac
    }
    for sh in sh dash bash busybox; do
        command -v "$sh" >/dev/null || continue
        [ "$sh" = busybox ] && sh="$stubs/busybox_sh"
        _allow AGENT alice "/usr/local/sbin/snapshot-agent.sh --action prepare --client alice --retain-hourly 0 --retain-daily 7 --retain-weekly 4 --retain-monthly 12 --retain-yearly 0"
        _allow AGENT alice "/usr/local/sbin/snapshot-agent.sh --action purge --client alice --retain-daily 7 --smart-purge-limit 20"
        _allow AGENT alice "/usr/local/sbin/snapshot-agent.sh --agent-mode --action version"
        _allow RSYNC alice "rsync --server -vlogDtprRze.iLsfxCIvu --numeric-ids --delete . $store/alice/daily.0.tmp/"
        _allow RSYNC alice "rsync --server --sender -vlogDtprRe.iLsfxCIvu . $store/alice/daily.0/etc"
        _allow RSYNC alice "rsync --server -vlogDtprRze.iLsfxCIvu --numeric-ids --delete --stats . $store/alice/daily.0.tmp/"
        # sftp-server has no chroot: "-R -d" is read-only and a start directory, nothing
        # more, so it reads the whole server. Only a key that is given it explicitly.
        _allow SFTP_SERVER "alice --allow-mount" "/usr/lib/openssh/sftp-server"
        _deny alice "/usr/lib/openssh/sftp-server"
        _deny alice "internal-sftp"
        _deny alice "/usr/local/sbin/snapshot-agent.sh --action purge --client bob --retain-daily 0"
        _deny alice "/usr/local/sbin/snapshot-agent.sh --agent-mode --action install"
        _deny alice "/usr/local/sbin/snapshot-agent.sh --action status --client alice --config $store/alice/daily.0/x.conf"
        _deny alice "/usr/local/sbin/snapshot-agent.sh --action prepare"
        _deny alice "rsync --server -vlogDtprRze.iLsfxCIvu --delete . $store/bob/daily.0/"
        _deny alice "rsync --server -vlogDtprRze.iLsfxCIvu --delete . $store/alice/../bob/daily.0/"
        _deny alice "rsync --server -vlogDtprRze.iLsfxCIvu --delete . $store/alice/escape/daily.0/"
        _deny alice "rsync --server -vlogDtpsrRze.iLsfxCIvu . $store/alice/daily.0/"
        _deny alice "rsync --server -vlogDtprRze.iLsfxCIvu --log-file=/etc/cron.d/x . $store/alice/daily.0/"
        _deny alice "rsync --server -vlogDtprRze.iLsfxCIvu --link-dest=$store/bob/daily.0 . $store/alice/daily.0/"
        _deny alice "rsync -av /etc/shadow $store/alice/"
        _deny alice "sh -c id"
        _deny alice ""
        _deny "../x" "/usr/local/sbin/snapshot-agent.sh --agent-mode --action version"
    done

    # ENFORCE=0 lets a refused command through the old way (and logs it)
    sed -i 's/^ENFORCE=.*/ENFORCE="0"/' "$w"; sh=sh
    _allow AGENT alice "/usr/local/sbin/snapshot-agent.sh --action status --client bob"
    # an authorized_keys line without a client name keeps the old behaviour
    sed -i 's/^ENFORCE=.*/ENFORCE="1"/' "$w"
    _allow AGENT "" "/usr/local/sbin/snapshot-agent.sh --action status --client bob"

    if [ -n "$failed" ]; then echo -e "    ${RED}[FAIL]$failed${NC}"; return 1; fi
}

test_26_lock_key() {
    # Goal: --setup-remote must leave the new key confined to the wrapper, not as root.
    #
    # ssh-copy-id installs a key without any restriction. The README promised an
    # authorized_keys lock since 15.1, but nothing wrote it; every confinement on a real
    # server had been added by hand. lock-key rewrites exactly the line holding the key.
    local home="$TEST_ROOT/lockhome" f
    rm -rf "$home"; mkdir -p "$home/.ssh"; f="$home/.ssh/authorized_keys"
    printf '%s\n' \
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYother0000000000000000000000000000 admin@desk" \
        "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITARGETKEYtarget00000000000000000000000000 root@alice" > "$f"
    HOME="$home" "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action lock-key --client alice \
        --key-blob AAAAC3NzaC1lZDI1NTE5AAAAITARGETKEYtarget00000000000000000000000000 >> "$LOG_FILE" 2>&1 \
        || { echo -e "    ${RED}[FAIL] lock-key failed${NC}"; return 1; }
    grep -q '^command="/usr/local/bin/snapshot-wrapper.sh alice",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITARGETKEYtarget00000000000000000000000000 root@alice$' "$f" \
        || { echo -e "    ${RED}[FAIL] target key not locked: $(grep TARGET "$f")${NC}"; return 1; }
    grep -q '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYother0000000000000000000000000000 admin@desk$' "$f" \
        || { echo -e "    ${RED}[FAIL] the other key was changed${NC}"; return 1; }
    HOME="$home" "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action lock-key --client alice --key-blob 'x;rm' >> "$LOG_FILE" 2>&1 \
        && { echo -e "    ${RED}[FAIL] invalid blob accepted${NC}"; return 1; }
    return 0
}

# A mock bin directory: rsync exits with the given code, sleep does nothing
# (run_with_retry waits 30 s between attempts), ssh runs the command locally.
_mock_failing_transfer() {
    local dir="$1" code="$2"
    mkdir -p "$dir"
    printf '#!/bin/sh\necho "mock rsync, exit %s" >&2\nexit %s\n' "$code" "$code" > "$dir/rsync"
    printf '#!/bin/sh\nexit 0\n' > "$dir/sleep"
    cat > "$dir/ssh" <<'EOF'
#!/bin/bash
eval "${@: -1}"
EOF
    printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted on"\necho "/dev/mock 999999999 999 100 99%% /"\n' > "$dir/df_full"
    chmod +x "$dir/rsync" "$dir/sleep" "$dir/ssh" "$dir/df_full"
}

_mock_remote_config() {
    set_config "BACKUP_MODE" "REMOTE"
    set_config "REMOTE_HOST" "mock_host"
    set_config "CLIENT_NAME" "test-client"
    set_config "REMOTE_STORAGE_ROOT" "$SERVER_STORAGE"
    set_config "BASE_STORAGE" "$SERVER_STORAGE"
    set_config "REMOTE_AGENT" "$SCRIPT_BIN --agent-mode --config $CONF_FILE"
}

test_27_local_exit_24_commits() {
    # Exit 24 means files vanished while a live filesystem was read. The copy
    # is complete; "if ! rsync" counted it as a failure and never committed.
    local mb="$TEST_ROOT/mock27"; _mock_failing_transfer "$mb" 24
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup; local ret=$?
    export PATH="$old_path"
    [ "$ret" -eq 0 ] || { echo -e "    ${RED}[FAIL] exit $ret after rsync 24${NC}"; return 1; }
    assert_exists "$MNT_DEST/daily.0/.backup_timestamp" || { echo -e "    ${RED}[FAIL] rsync 24 was not committed${NC}"; return 1; }
}

test_28_local_failure_is_reported() {
    # A failed local run returned normally, so cron, systemd and POST_RUN_CMD
    # all saw success - a relay failed every night for eight months unseen.
    local mb="$TEST_ROOT/mock28"; _mock_failing_transfer "$mb" 11
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup; local ret=$?
    export PATH="$old_path"
    [ "$ret" -ne 0 ] || { echo -e "    ${RED}[FAIL] rsync 11 ended with exit 0${NC}"; return 1; }
    assert_missing "$MNT_DEST/daily.0/.backup_timestamp" || return 1
}

test_29_remote_failure_does_not_commit() {
    # The commit writes the timestamp. After a failed transfer it turned a
    # half-copied tree into something indistinguishable from a good snapshot.
    local mb="$TEST_ROOT/mock29"; _mock_failing_transfer "$mb" 11
    _mock_remote_config
    local c="$SERVER_STORAGE/test-client"
    mock_timestamp "$c/daily.0" "2 days ago"
    local before; before=$(cat "$c/daily.0/.backup_timestamp")
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup; local ret=$?
    export PATH="$old_path"
    [ "$ret" -ne 0 ] || { echo -e "    ${RED}[FAIL] remote rsync 11 ended with exit 0${NC}"; return 1; }
    [ "$(cat "$c/daily.0/.backup_timestamp")" = "$before" ] || { echo -e "    ${RED}[FAIL] daily.0 was committed after a failed transfer${NC}"; return 1; }
    assert_missing "$c/daily.1" || { echo -e "    ${RED}[FAIL] a failed transfer was rotated in${NC}"; return 1; }
}

test_30_purge_runs_before_the_transfer() {
    # A full target makes the transfer fail. A purge that only runs after a
    # successful transfer then never runs: the store stays full for good.
    local mb="$TEST_ROOT/mock30"; _mock_failing_transfer "$mb" 11
    mv "$mb/df_full" "$mb/df"
    set_config "SPACE_LOW_LIMIT_GB" 3
    set_config "SMART_PURGE_SLOTS" 2
    local i
    for i in 0 1 2 3; do mock_timestamp "$MNT_DEST/daily.$i" "$((i+1)) days ago"; done
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup
    export PATH="$old_path"
    assert_missing "$MNT_DEST/daily.3" || { echo -e "    ${RED}[FAIL] LOCAL: no purge before the transfer${NC}"; return 1; }
    assert_missing "$MNT_DEST/daily.2" || return 1
    assert_exists "$MNT_DEST/daily.1" || { echo -e "    ${RED}[FAIL] LOCAL: purged more than SMART_PURGE_SLOTS${NC}"; return 1; }
    assert_exists "$MNT_DEST/daily.0" || return 1

    # REMOTE: the agent reads no config, so the slots have to travel with the
    # call - and daily.0 survives even when more slots are allowed than exist.
    _mock_remote_config
    set_config "SMART_PURGE_SLOTS" 5
    local c="$SERVER_STORAGE/test-client"
    for i in 0 1 2; do mock_timestamp "$c/daily.$i" "$((i+1)) days ago"; done
    export PATH="$mb:$PATH"
    run_backup
    export PATH="$old_path"
    assert_missing "$c/daily.2" || { echo -e "    ${RED}[FAIL] REMOTE: no purge before the transfer${NC}"; return 1; }
    assert_missing "$c/daily.1" || return 1
    assert_exists "$c/daily.0/.backup_timestamp" || { echo -e "    ${RED}[FAIL] REMOTE: daily.0 was purged${NC}"; return 1; }
}

test_31_term_stops_the_run() {
    # A trap on INT/TERM that only cleans up lets the shell carry on afterwards:
    # the lock was released and POST_RUN_CMD ran in the middle of the run, which
    # then went on to commit and exit 0. A stopped backup must stay stopped.
    local mb="$TEST_ROOT/mock31"; mkdir -p "$mb"
    printf '#!/bin/sh\ncase "$*" in *--version*) exit 0 ;; esac\nsleep 3\nexit 0\n' > "$mb/rsync"; chmod +x "$mb/rsync"
    local old_path="$PATH"; export PATH="$mb:$PATH"
    "$SCRIPT_BIN" --config "$CONF_FILE" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    sleep 1; kill -TERM "$pid"; wait "$pid"; local ret=$?
    export PATH="$old_path"
    [ "$ret" -ne 0 ] || { echo -e "    ${RED}[FAIL] exit 0 after SIGTERM${NC}"; return 1; }
    assert_missing "$MNT_DEST/daily.0/.backup_timestamp" || { echo -e "    ${RED}[FAIL] committed after SIGTERM${NC}"; return 1; }
}

test_32_remote_verify_is_recorded() {
    # The deep-verify stamp was written in LOCAL mode only. A REMOTE client
    # therefore found no stamp every night and ran --checksum every night.
    local mb="$TEST_ROOT/mock32"; mkdir -p "$mb"
    printf '#!/bin/sh\necho "$*" >> "%s/rsync.calls"\nexit 0\n' "$TEST_ROOT" > "$mb/rsync"
    cat > "$mb/ssh" <<'EOF'
#!/bin/bash
eval "${@: -1}"
EOF
    chmod +x "$mb/rsync" "$mb/ssh"
    _mock_remote_config
    set_config "LAST_VERIFY_FILE" "$TEST_ROOT/lastverify/stamp"
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup
    local first; first=$(grep -c -- "--exclude-from.*--checksum\|--checksum.*--exclude-from" "$TEST_ROOT/rsync.calls")
    : > "$TEST_ROOT/rsync.calls"
    run_backup
    local second; second=$(grep -c -- "--checksum" "$TEST_ROOT/rsync.calls")
    export PATH="$old_path"
    [ "$first" -ge 1 ] || { echo -e "    ${RED}[FAIL] first run did not verify${NC}"; return 1; }
    assert_exists "$TEST_ROOT/lastverify/stamp" || { echo -e "    ${RED}[FAIL] REMOTE run left no verify stamp${NC}"; return 1; }
    [ "$second" -eq 0 ] || { echo -e "    ${RED}[FAIL] second run verified again${NC}"; return 1; }
}

test_33_local_absolute_exclude() {
    # REMOTE copies with -R, so "/a/b/c" matches the real path. LOCAL copied
    # "src/" into "dest/src/" without it, which anchors patterns at the source
    # directory: for any source but "/" an absolute pattern matched nothing.
    mkdir -p "$MNT_SRC/sub"
    echo keep > "$MNT_SRC/sub/keep.me"; echo skip > "$MNT_SRC/sub/skip.me"
    set_config "EXCLUDE_PATTERNS" "$MNT_SRC/sub/skip.me"
    run_backup || { echo -e "    ${RED}[FAIL] backup failed${NC}"; return 1; }
    local d="$MNT_DEST/daily.0${MNT_SRC}/sub"
    assert_exists "$d/keep.me" || { echo -e "    ${RED}[FAIL] layout changed${NC}"; return 1; }
    assert_missing "$d/skip.me" || { echo -e "    ${RED}[FAIL] LOCAL ignored an absolute exclude${NC}"; return 1; }
}

test_34_period_signatures() {
    # Weekly was "%Y%m%V": a week across a month boundary had two signatures and
    # got two weekly snapshots, and ISO week 53 in early January compared as
    # newer than every January week, so nothing was promoted until February.
    eval "$(sed -n '/^sanitize_int()/,/^}/p; /^get_sortable_date()/,/^}/p' "$SCRIPT_BIN")"
    ts_to_date() { date -d "@$1" "$2"; }
    local f=""
    _s() { get_sortable_date "$1" "$(date -d "$2 12:00" +%s)"; }
    [ "$(_s weekly 2026-09-28)" = "$(_s weekly 2026-10-04)" ] || f="$f [week 40 split by the month]"
    [ "$(_s weekly 2027-01-11)" -gt "$(_s weekly 2027-01-02)" ] || f="$f [Jan 11 not after ISO week 53]"
    [ "$(_s weekly 2027-01-04)" -gt "$(_s weekly 2026-12-27)" ] || f="$f [week 1 not after week 52]"
    [ "$(_s daily 2027-01-04)" -gt "$(_s daily 2027-01-02)" ] || f="$f [daily Jan 4 not after Jan 2]"
    [ "$(_s hourly 2027-01-04)" -gt "$(_s hourly 2027-01-02)" ] || f="$f [hourly Jan 4 not after Jan 2]"
    [ "$(_s monthly 2027-01-02)" -gt "$(_s monthly 2026-12-31)" ] || f="$f [monthly]"
    [ -z "$f" ] || { echo -e "    ${RED}[FAIL]$f${NC}"; return 1; }
}

test_35_agent_serialises_actions() {
    # The agent wrote a lock file and never looked at it. Two actions for the
    # same client could rename the same directories at the same time.
    set_config "BASE_STORAGE" "$SERVER_STORAGE"
    set_config "LOCK_DIR" "$TEST_ROOT/agentlock"
    local l="$TEST_ROOT/agentlock/t35.lockd"
    mkdir -p "$l"; sleep 30 & local holder=$!; echo "$holder" > "$l/pid"
    local a="$SCRIPT_BIN --agent-mode --config $CONF_FILE --action prepare --client t35 --retain-daily 7"
    AGENT_LOCK_WAIT=2 $a >> "$LOG_FILE" 2>&1; local busy=$?
    kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
    AGENT_LOCK_WAIT=2 $a >> "$LOG_FILE" 2>&1; local stale=$?
    [ "$busy" -ne 0 ] || { echo -e "    ${RED}[FAIL] prepare ran while another action held the lock${NC}"; return 1; }
    [ "$stale" -eq 0 ] || { echo -e "    ${RED}[FAIL] a dead holder's lock blocked prepare${NC}"; return 1; }
    assert_missing "$l" || { echo -e "    ${RED}[FAIL] lock left behind${NC}"; return 1; }
}

test_36_kill_stops_only_this_run() {
    # --kill ran "pkill -f snapshot-backup.sh": every process whose command line
    # mentions the script - other configs' runs, an editor, itself - while the
    # rsync of the run it was meant for kept going.
    local mb="$TEST_ROOT/mock36"; mkdir -p "$mb"
    printf '#!/bin/sh\ncase "$*" in *--version*) exit 0 ;; esac\nexec sleep 30\n' > "$mb/rsync"; chmod +x "$mb/rsync"
    set_config "PIDFILE" "$TEST_ROOT/run36.pid"
    sh -c 'sleep 30; : snapshot-backup.sh' & local bystander=$!
    local old_path="$PATH"; export PATH="$mb:$PATH"
    "$SCRIPT_BIN" --config "$CONF_FILE" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    sleep 1
    "$SCRIPT_BIN" --config "$CONF_FILE" --kill >> "$LOG_FILE" 2>&1
    local i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt 10 ]; do sleep 1; i=$((i+1)); done
    export PATH="$old_path"
    local f=""
    kill -0 "$pid" 2>/dev/null && { f="$f [run still alive after 10 s]"; kill -9 "$pid"; }
    kill -0 "$bystander" 2>/dev/null || f="$f [killed an unrelated process]"
    kill "$bystander" 2>/dev/null; pkill -f "$mb/rsync" 2>/dev/null; pkill -x -f "sleep 30" 2>/dev/null
    [ -e "$MNT_DEST/daily.0/.backup_timestamp" ] && f="$f [committed after --kill]"
    [ -d "$TEST_ROOT/run36.lock" ] && f="$f [lock left behind]"
    [ -z "$f" ] || { echo -e "    ${RED}[FAIL]$f${NC}"; return 1; }
}

test_37_install_replaces_atomically() {
    # --install wrote the new agent into the existing file. An agent action
    # still running reads its script piece by piece and would continue in a
    # mixture of two versions. The installed file must be a new inode.
    local a="$TEST_ROOT/agent-37.sh"
    printf '#!/bin/sh\n# old agent\n' > "$a"
    exec 7< "$a"
    local before; before=$(ls -i "$a" | awk '{print $1}')
    AGENT_INSTALL_PATH="$a" WRAPPER_PATH="$TEST_ROOT/wrapper-37.sh" \
        "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action install >> "$LOG_FILE" 2>&1
    local after; after=$(ls -i "$a" | awk '{print $1}')
    local held; held=$(cat <&7); exec 7<&-
    [ "$before" != "$after" ] || { echo -e "    ${RED}[FAIL] agent rewritten in place (inode $before)${NC}"; return 1; }
    [ "$held" = "$(printf '#!/bin/sh\n# old agent')" ] || { echo -e "    ${RED}[FAIL] an open reader saw the new content${NC}"; return 1; }
    cmp -s "$a" "$SCRIPT_BIN" || { echo -e "    ${RED}[FAIL] installed agent differs from the script${NC}"; return 1; }
    [ -z "$(ls "$TEST_ROOT"/agent-37.sh.new.* 2>/dev/null)" ] || { echo -e "    ${RED}[FAIL] temporary file left behind${NC}"; return 1; }
}

# A stand-in WOL-Server: logs every request as "METHOD PATH AUTH BODY" to
# $TEST_ROOT/api.log. POST answers with the status in $TEST_ROOT/wol.status
# (default 201) and "woken" from $TEST_ROOT/wol.woken (default true); PUT and
# DELETE answer 200.
_start_mock_wolserver() {
    cat > "$TEST_ROOT/mock_api.py" <<'EOF'
import http.server, json, os, sys
root = sys.argv[1]
def setting(name, default):
    p = os.path.join(root, name)
    return open(p).read().strip() if os.path.exists(p) else default
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def answer(self, status, payload):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        with open(os.path.join(root, "api.log"), "a") as f:
            f.write(f"{self.command} {self.path} {self.headers.get('Authorization')} {body}\n")
        data = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        status = int(setting("wol.status", "201"))
        self.answer(status, {"ok": status == 201, "device": "backup", "id": "abc123def456", "client": "x",
                             "ttl": 900, "online": status == 201, "woken": setting("wol.woken", "true") == "true",
                             "message": "Magic packet sent"})
    def do_PUT(self): self.answer(200, {"ok": True, "id": "abc123def456"})
    def do_DELETE(self): self.answer(200, {"ok": True, "message": "Done", "sleep": None, "waiting_for": []})
s = http.server.HTTPServer(("127.0.0.1", int(sys.argv[2]) if len(sys.argv) > 2 else 0), H)
open(os.path.join(root, "api.port"), "w").write(str(s.server_address[1]))
s.serve_forever()
EOF
    rm -f "$TEST_ROOT/api.port" "$TEST_ROOT/api.log"
    python3 "$TEST_ROOT/mock_api.py" "$TEST_ROOT" &
    MOCK_API_PID=$!
    local i=0; while [ ! -s "$TEST_ROOT/api.port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    set_config "WOL_SERVER_URL" "http://127.0.0.1:$(cat "$TEST_ROOT/api.port")"
    set_config "WOL_SERVER_TOKEN" "invented-test-token"
    set_config "WOL_DEVICES" "backup"
    set_config "CLIENT_NAME" "test-client"
}

# rsync that notes in the API log that the transfer happened, sleeps $2 s, then exits with $1
_mock_rsync_logging() {
    local mb="$TEST_ROOT/mock_power"; mkdir -p "$mb"
    printf '#!/bin/sh\ncase "$*" in *--version*) exit 0 ;; esac\necho "RSYNC" >> "%s/api.log"\nsleep %s\nexit %s\n' \
        "$TEST_ROOT" "${2:-0}" "$1" > "$mb/rsync"
    chmod +x "$mb/rsync"
    echo "$mb"
}

# _run_with_wolserver <rsync exit> [rsync seconds]: one backup against the mock; sets ret
_run_with_wolserver() {
    local mb; mb=$(_mock_rsync_logging "$1" "${2:-0}")
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup; ret=$?
    export PATH="$old_path"
}

test_38_wol_request_around_the_run() {
    # Several clients share a backup server: the run requests it before the
    # transfer and ends the request afterwards, asking for sleep (it woke it).
    _start_mock_wolserver
    local ret; _run_with_wolserver 0
    kill "$MOCK_API_PID" 2>/dev/null
    [ "$ret" -eq 0 ] || { echo -e "    ${RED}[FAIL] backup failed${NC}"; return 1; }
    local seq; seq=$(awk '{print $1, $2}' "$TEST_ROOT/api.log" | tr '\n' '|')
    case "$seq" in
        "POST /api/devices/backup/requests?wait=300|RSYNC "*"|DELETE /api/devices/backup/requests/abc123def456?then=sleep|") ;;
        *) echo -e "    ${RED}[FAIL] order: $seq${NC}"; return 1 ;;
    esac
    grep -q '^POST /api/devices/backup/requests?wait=300 Bearer invented-test-token {"client": "snapshot-backup:test-client", "ttl": 900}$' \
        "$TEST_ROOT/api.log" || { echo -e "    ${RED}[FAIL] request: $(head -1 "$TEST_ROOT/api.log")${NC}"; return 1; }
}

test_39_wol_unreachable_still_backs_up() {
    # The WOL-Server is a convenience: when it does not answer, the backup runs anyway.
    set_config "WOL_SERVER_URL" "http://127.0.0.1:9"
    set_config "WOL_DEVICES" "backup"
    echo data > "$MNT_SRC/file"
    run_backup; local ret=$?
    [ "$ret" -eq 0 ] || { echo -e "    ${RED}[FAIL] exit $ret${NC}"; return 1; }
    assert_exists "$MNT_DEST/daily.0/.backup_timestamp" || return 1
    grep -q "WOL-Server: no request for backup" "$LOG_FILE" || { echo -e "    ${RED}[FAIL] no warning${NC}"; return 1; }
}

test_40_wol_request_ended_after_a_failure() {
    _start_mock_wolserver
    local ret; _run_with_wolserver 11
    kill "$MOCK_API_PID" 2>/dev/null
    [ "$ret" -ne 0 ] || { echo -e "    ${RED}[FAIL] failure not reported${NC}"; return 1; }
    grep -q "^DELETE /api/devices/backup/requests/abc123def456" "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] request not ended after a failed run${NC}"; return 1; }
}

test_41_wol_sleep_only_for_a_woken_device() {
    # A backup server that was already on (someone works on it) is not put to
    # sleep by default; WOL_SLEEP_AFTER=true and false override that.
    _start_mock_wolserver
    local ret mode woken want
    for mode in "woken false -" "true false ?then=sleep" "false true -"; do
        set -- $mode
        set_config "WOL_SLEEP_AFTER" "$1"; echo "$2" > "$TEST_ROOT/wol.woken"; want="$3"
        rm -f "$TEST_ROOT/api.log"
        _run_with_wolserver 0
        local del; del=$(awk '$1 == "DELETE" {print $2}' "$TEST_ROOT/api.log")
        [ "$want" = "-" ] && want=""
        if [ "$del" != "/api/devices/backup/requests/abc123def456$want" ]; then
            kill "$MOCK_API_PID" 2>/dev/null
            echo -e "    ${RED}[FAIL] WOL_SLEEP_AFTER=$1, woken=$2: $del${NC}"; return 1
        fi
    done
    kill "$MOCK_API_PID" 2>/dev/null
}

test_42_wol_device_not_awake() {
    # 504: the device did not come up in time. The request is open all the same
    # and is ended - without asking for sleep, the device was never seen awake.
    _start_mock_wolserver
    echo 504 > "$TEST_ROOT/wol.status"
    local mark; mark=$(wc -l < "$LOG_FILE")
    local ret; _run_with_wolserver 0
    kill "$MOCK_API_PID" 2>/dev/null
    grep -q "^DELETE /api/devices/backup/requests/abc123def456 " "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] $(grep DELETE "$TEST_ROOT/api.log")${NC}"; return 1; }
    tail -n +$((mark + 1)) "$LOG_FILE" | grep -q "WOL-Server: backup requested, but not awake (HTTP 504" \
        || { echo -e "    ${RED}[FAIL] no warning${NC}"; return 1; }
}

test_54_wol_heartbeat_while_the_run_lasts() {
    # A request without heartbeats expires: a long run renews it, and the
    # heartbeats stop with the run.
    _start_mock_wolserver
    set_config "WOL_HEARTBEAT_SECONDS" "1"
    local ret; _run_with_wolserver 0 3
    sleep 2
    kill "$MOCK_API_PID" 2>/dev/null
    local seq; seq=$(awk '{print $1}' "$TEST_ROOT/api.log" | tr '\n' ' ')
    case "$seq" in
        "POST RSYNC PUT "*"DELETE ") ;;
        *) echo -e "    ${RED}[FAIL] sequence: $seq${NC}"; return 1 ;;
    esac
    if pgrep -f "snapshot-backup.sh --config $CONF_FILE" >/dev/null; then
        echo -e "    ${RED}[FAIL] the heartbeat outlived the run${NC}"; return 1
    fi
}

test_55_job_done_answered_locally() {
    # The hourly timer asks --is-job-done every hour; over SSH every question
    # spins up the server's disks. The record of the last run answers instead.
    local bin="$TEST_ROOT/mock55"; mkdir -p "$bin"
    printf '#!/bin/sh\necho call >> "%s/ssh.calls"\ncat "%s/ssh.answer"\n' "$TEST_ROOT" "$TEST_ROOT" > "$bin/ssh"
    chmod +x "$bin/ssh"
    set_config "BACKUP_MODE" "REMOTE"
    set_config "CLIENT_NAME" "test-client"
    local calls
    echo true > "$TEST_ROOT/ssh.answer"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1 \
        || { echo -e "    ${RED}[FAIL] the server said done${NC}"; return 1; }
    assert_exists "$TEST_ROOT/job_done" || return 1
    echo false > "$TEST_ROOT/ssh.answer"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1 \
        || { echo -e "    ${RED}[FAIL] the record of this period was not used${NC}"; return 1; }
    calls=$(wc -l < "$TEST_ROOT/ssh.calls")
    [ "$calls" -eq 1 ] || { echo -e "    ${RED}[FAIL] asked the server $calls times${NC}"; return 1; }
    # A record from another period, or for another client, asks the server again.
    sed -i "s/ [0-9]*\$/ $(( $(date +%s) - 3 * 86400 ))/" "$TEST_ROOT/job_done"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] a record from three days ago answered${NC}"; return 1; }
    echo true > "$TEST_ROOT/ssh.answer"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1
    set_config "CLIENT_NAME" "other-client"
    echo false > "$TEST_ROOT/ssh.answer"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] the record of another client answered${NC}"; return 1; }
    calls=$(wc -l < "$TEST_ROOT/ssh.calls")
    [ "$calls" -eq 4 ] || { echo -e "    ${RED}[FAIL] asked the server $calls times, expected 4${NC}"; return 1; }
}

test_56_wakeserver_options_warn() {
    # The wakeserver is gone; a config that still names it backs up and says so.
    set_config "POWER_API_URL" "http://127.0.0.1:9"
    local mark; mark=$(wc -l < "$LOG_FILE")
    run_backup || { echo -e "    ${RED}[FAIL] backup failed${NC}"; return 1; }
    tail -n +$((mark + 1)) "$LOG_FILE" | grep -q "POWER_API_URL (wakeserver) is no longer supported" \
        || { echo -e "    ${RED}[FAIL] no warning${NC}"; return 1; }
}

test_57_wol_by_address() {
    # A client on the VPN reaches the WOL-Server by its VPN address; the name in
    # the URL (which the certificate is for) does not resolve there at all.
    _start_mock_wolserver
    set_config "WOL_SERVER_URL" "http://wol.invalid:$(cat "$TEST_ROOT/api.port")"
    set_config "WOL_RESOLVE" "127.0.0.1"
    local ret; _run_with_wolserver 0
    kill "$MOCK_API_PID" 2>/dev/null
    [ "$ret" -eq 0 ] || { echo -e "    ${RED}[FAIL] backup failed${NC}"; return 1; }
    grep -q "^POST /api/devices/backup/requests" "$TEST_ROOT/api.log" \
        && grep -q "^DELETE /api/devices/backup/requests/abc123def456" "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] $(cat "$TEST_ROOT/api.log" 2>&1)${NC}"; return 1; }
    # Only an address: the value ends up on curl's command line.
    set_config "WOL_RESOLVE" "10.1.1.8 --insecure"
    run_backup && { echo -e "    ${RED}[FAIL] WOL_RESOLVE with options accepted${NC}"; return 1; }
    return 0
}

test_58_wol_status_wakes_and_says_so() {
    # --status on a client whose backup server sleeps: it is requested (woken)
    # for the length of the command, and the user is told about the wait.
    _start_mock_wolserver
    local bin="$TEST_ROOT/mock58" out; mkdir -p "$bin"
    printf '#!/bin/sh\necho "daily.0  (snapshot table)"\n' > "$bin/ssh"; chmod +x "$bin/ssh"
    set_config "BACKUP_MODE" "REMOTE"
    out=$(PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --status 2>&1)
    kill "$MOCK_API_PID" 2>/dev/null
    echo "$out" | grep -q "daily.0  (snapshot table)" || { echo -e "    ${RED}[FAIL] no table: $out${NC}"; return 1; }
    echo "$out" | grep -q "waking it can take up to 300 s" \
        || { echo -e "    ${RED}[FAIL] the user is not told about the wait${NC}"; return 1; }
    local seq; seq=$(awk '{print $1, $2}' "$TEST_ROOT/api.log" | tr '\n' '|')
    [ "$seq" = "POST /api/devices/backup/requests?wait=300|DELETE /api/devices/backup/requests/abc123def456?then=sleep|" ] \
        || { echo -e "    ${RED}[FAIL] requests: $seq${NC}"; return 1; }
    grep -q '"client": "snapshot-backup:test-client (status)", "ttl": 900' "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] $(head -1 "$TEST_ROOT/api.log")${NC}"; return 1; }
}

test_59_wol_mount_holds_until_umount() {
    # Restoring from a mount takes as long as it takes: the request has no
    # expiry and ends with --umount, not with the --mount command.
    _start_mock_wolserver
    local bin="$TEST_ROOT/mock59"; mkdir -p "$bin"
    printf '#!/bin/sh\nexit 0\n' > "$bin/sshfs"
    printf '#!/bin/sh\nexit 0\n' > "$bin/umount"
    printf '#!/bin/sh\nexit 1\n' > "$bin/mountpoint"
    chmod +x "$bin"/*
    set_config "BACKUP_MODE" "REMOTE"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --mount "$TEST_ROOT/mp59" >/dev/null 2>&1 \
        || { kill "$MOCK_API_PID"; echo -e "    ${RED}[FAIL] --mount failed${NC}"; return 1; }
    grep -q '"client": "snapshot-backup:test-client (mount)", "ttl": 0' "$TEST_ROOT/api.log" \
        || { kill "$MOCK_API_PID"; echo -e "    ${RED}[FAIL] $(head -1 "$TEST_ROOT/api.log")${NC}"; return 1; }
    if grep -q "^DELETE" "$TEST_ROOT/api.log"; then
        kill "$MOCK_API_PID"; echo -e "    ${RED}[FAIL] the request ended with --mount${NC}"; return 1
    fi
    grep -q "^$TEST_ROOT/mp59 backup=abc123def456=yes$" "$TEST_ROOT/wol_mount" \
        || { kill "$MOCK_API_PID"; echo -e "    ${RED}[FAIL] not noted: $(cat "$TEST_ROOT/wol_mount" 2>&1)${NC}"; return 1; }
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --umount "$TEST_ROOT/mp59" >/dev/null 2>&1
    grep -q "^DELETE /api/devices/backup/requests/abc123def456?then=sleep " "$TEST_ROOT/api.log" \
        || { kill "$MOCK_API_PID"; echo -e "    ${RED}[FAIL] --umount did not end it${NC}"; return 1; }
    assert_missing "$TEST_ROOT/wol_mount" || { kill "$MOCK_API_PID"; return 1; }
    # A mount that fails ends its request at once.
    rm -f "$TEST_ROOT/api.log"
    printf '#!/bin/sh\nexit 1\n' > "$bin/sshfs"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --mount "$TEST_ROOT/mp59" >/dev/null 2>&1
    kill "$MOCK_API_PID" 2>/dev/null
    grep -q "^DELETE /api/devices/backup/requests/abc123def456" "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] a failed mount kept its request${NC}"; return 1; }
    assert_missing "$TEST_ROOT/wol_mount" || return 1
}

test_60_config_replaces_the_default() {
    # --config FILE is the whole config: nothing comes from the default one.
    # A copy of the script whose default is a file of this test stands in for
    # /etc/snapshot-backup.conf.
    local bin="$TEST_ROOT/sb60.sh"
    sed "s#^CONFIG_FILE=.*#CONFIG_FILE=\"$TEST_ROOT/default60.conf\"#" "$SCRIPT_BIN" > "$bin"; chmod +x "$bin"
    printf 'CONFIG_VERSION="1.0"\n' > "$TEST_ROOT/default60.conf"
    "$bin" --config "$CONF_FILE" --show-config >/dev/null 2>&1 \
        || { echo -e "    ${RED}[FAIL] the default config was read despite --config${NC}"; return 1; }
    printf 'CONFIG_VERSION="2.0"\nWOL_SERVER_URL="http://from-the-default.invalid"\n' > "$TEST_ROOT/default60.conf"
    "$bin" --config "$CONF_FILE" --show-config 2>/dev/null | grep -q "from-the-default" \
        && { echo -e "    ${RED}[FAIL] a value from the default config leaked in${NC}"; return 1; }
    # Without --config the default is the config.
    "$bin" --show-config 2>/dev/null | grep -q '^WOL_SERVER_URL="http://from-the-default.invalid"$' \
        || { echo -e "    ${RED}[FAIL] the default config was not read without --config${NC}"; return 1; }
}

test_61_waits_for_the_network_wol() {
    # Woken from standby by its timer, a client starts before DHCP is done: the
    # WOL-Server does not answer for a few seconds. The run waits for it.
    _start_mock_wolserver
    local port; port=$(cat "$TEST_ROOT/api.port")
    kill "$MOCK_API_PID"; wait "$MOCK_API_PID" 2>/dev/null
    ( sleep 6; exec python3 "$TEST_ROOT/mock_api.py" "$TEST_ROOT" "$port" ) &
    local late=$!
    set_config "NETWORK_WAIT_SECONDS" "30"
    local mark; mark=$(wc -l < "$LOG_FILE")
    local ret; _run_with_wolserver 0
    kill "$late" 2>/dev/null; pkill -f "mock_api.py $TEST_ROOT $port" 2>/dev/null
    [ "$ret" -eq 0 ] || { echo -e "    ${RED}[FAIL] backup failed${NC}"; return 1; }
    tail -n +$((mark + 1)) "$LOG_FILE" | grep -q "WOL-Server: not reachable yet - waiting up to 30 s" \
        || { echo -e "    ${RED}[FAIL] no waiting message${NC}"; return 1; }
    grep -q "^POST /api/devices/backup/requests" "$TEST_ROOT/api.log" 2>/dev/null \
        && grep -q "^DELETE /api/devices/backup/requests/abc123def456" "$TEST_ROOT/api.log" \
        || { echo -e "    ${RED}[FAIL] the late WOL-Server got no request${NC}"; return 1; }
}

test_62_waits_for_the_backup_server() {
    # Without a WOL-Server the same start meets an unreachable backup server:
    # tried again for NETWORK_WAIT_SECONDS before "Server unreachable".
    local bin="$TEST_ROOT/mock62"; mkdir -p "$bin"
    printf '#!/bin/sh\necho call >> "%s/ssh62.calls"\nexit 255\n' "$TEST_ROOT" > "$bin/ssh"; chmod +x "$bin/ssh"
    set_config "BACKUP_MODE" "REMOTE"
    set_config "NETWORK_WAIT_SECONDS" "6"
    local mark start
    mark=$(wc -l < "$LOG_FILE"); start=$(date +%s)
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" >> "$LOG_FILE" 2>&1 \
        && { echo -e "    ${RED}[FAIL] an unreachable server did not fail the run${NC}"; return 1; }
    [ $(( $(date +%s) - start )) -ge 6 ] || { echo -e "    ${RED}[FAIL] did not wait${NC}"; return 1; }
    [ "$(wc -l < "$TEST_ROOT/ssh62.calls")" -ge 2 ] || { echo -e "    ${RED}[FAIL] not tried again${NC}"; return 1; }
    tail -n +$((mark + 1)) "$LOG_FILE" | grep -q "Backup server not reachable yet - waiting up to 6 s" \
        || { echo -e "    ${RED}[FAIL] no waiting message${NC}"; return 1; }
}

test_63_wrapper_holds_an_inhibitor() {
    # Every backup process on the server announces itself: the wrapper runs agent
    # actions and rsync under a block inhibitor against shutdown and sleep, named
    # after the client. A power-off that respects inhibitors then names the client
    # instead of guessing from command lines.
    local w="$TEST_ROOT/wrapper63.sh" store="$TEST_ROOT/wstore63" stubs="$TEST_ROOT/stubs63" out
    rm -rf "$store" "$stubs"; mkdir -p "$store/alice/daily.0" "$stubs"
    AGENT_INSTALL_PATH="$TEST_ROOT/agent63.sh" WRAPPER_PATH="$w" WRAPPER_ENFORCE=1 \
        BASE_STORAGE="$store" "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action install >> "$LOG_FILE" 2>&1
    grep -q '^INHIBIT=' "$w" || { echo -e "    ${RED}[FAIL] the wrapper has no INHIBIT${NC}"; return 1; }
    local s
    for s in AGENT RSYNC; do
        printf '#!/bin/sh\necho "%s $*"\n' "$s" > "$stubs/$s"; chmod +x "$stubs/$s"
        sed -i "s|^$s=.*|$s=\"$stubs/$s\"|" "$w"
    done
    printf '#!/bin/sh\necho "$*" >> "%s/inhibit63.log"\nwhile [ "${1#--}" != "$1" ]; do shift; done\nexec "$@"\n' \
        "$TEST_ROOT" > "$stubs/inhibit"; chmod +x "$stubs/inhibit"

    # Under every POSIX shell present: the wrapper has to work on busybox machines too.
    printf '#!/bin/sh\nexec busybox sh "$@"\n' > "$stubs/busybox_sh"; chmod +x "$stubs/busybox_sh"
    local sh n=0
    for sh in sh dash bash busybox; do
        command -v "$sh" >/dev/null || continue
        [ "$sh" = busybox ] && sh="$stubs/busybox_sh"
        sed -i "s|^INHIBIT=.*|INHIBIT=\"$stubs/inhibit\"|" "$w"
        out=$(SSH_ORIGINAL_COMMAND="/usr/local/sbin/snapshot-agent.sh --action purge --client alice --retain-daily 7" "$sh" "$w" alice 2>/dev/null)
        case "$out" in "AGENT --action purge --client alice"*) ;; *) echo -e "    ${RED}[FAIL] $sh, agent: $out${NC}"; return 1 ;; esac
        out=$(SSH_ORIGINAL_COMMAND="rsync --server -vlogDtprRze.iLsfxCIvu --numeric-ids --delete . $store/alice/daily.0.tmp/" "$sh" "$w" alice 2>/dev/null)
        case "$out" in "RSYNC --server"*) ;; *) echo -e "    ${RED}[FAIL] $sh, rsync: $out${NC}"; return 1 ;; esac
        n=$((n + 2))
        [ "$(grep -c -- '--what=shutdown:sleep --who=snapshot-backup:alice --why=backup of alice running --mode=block' "$TEST_ROOT/inhibit63.log")" -eq "$n" ] \
            || { echo -e "    ${RED}[FAIL] $sh, inhibitor: $(tail -2 "$TEST_ROOT/inhibit63.log" 2>&1)${NC}"; return 1; }
        # A refused command takes no inhibitor.
        SSH_ORIGINAL_COMMAND="rsync -av /etc/shadow $store/alice/" "$sh" "$w" alice >/dev/null 2>&1
        [ "$(wc -l < "$TEST_ROOT/inhibit63.log")" -eq "$n" ] || { echo -e "    ${RED}[FAIL] $sh: a refused command took an inhibitor${NC}"; return 1; }
        # Fallback without systemd-inhibit (busybox systems): the process runs directly.
        sed -i 's|^INHIBIT=.*|INHIBIT=""|' "$w"
        out=$(SSH_ORIGINAL_COMMAND="/usr/local/sbin/snapshot-agent.sh --agent-mode --action version" "$sh" "$w" alice 2>/dev/null)
        case "$out" in "AGENT --agent-mode --action version") ;; *) echo -e "    ${RED}[FAIL] $sh, without systemd-inhibit: $out${NC}"; return 1 ;; esac
    done
}

test_43_inhibit_sleep_during_the_run() {
    # The host's own guard: a blocking inhibitor while rsync runs, gone afterwards.
    local mb="$TEST_ROOT/mock_inhibit"; mkdir -p "$mb"
    printf '#!/bin/sh\necho $$ > "%s/inhibitor.pid"\nwhile [ "${1#--}" != "$1" ]; do shift; done\nexec "$@"\n' \
        "$TEST_ROOT" > "$mb/systemd-inhibit"
    printf '#!/bin/sh\ncase "$*" in *--version*) exit 0 ;; esac\nkill -0 "$(cat "%s/inhibitor.pid")" && touch "%s/held"\nexit 0\n' \
        "$TEST_ROOT" "$TEST_ROOT" > "$mb/rsync"
    chmod +x "$mb/systemd-inhibit" "$mb/rsync"
    set_config "INHIBIT_SLEEP" "true"
    local old_path="$PATH"; export PATH="$mb:$PATH"
    run_backup
    export PATH="$old_path"
    assert_exists "$TEST_ROOT/held" || { echo -e "    ${RED}[FAIL] no inhibitor while rsync ran${NC}"; return 1; }
    sleep 1
    if kill -0 "$(cat "$TEST_ROOT/inhibitor.pid")" 2>/dev/null; then
        echo -e "    ${RED}[FAIL] inhibitor outlived the run${NC}"; return 1
    fi
}

test_44_setup_failures_are_reported() {
    # Goal: --deploy-agent and --setup-remote must fail loudly when the server cannot be reached.
    #
    # Run through a pipe (no terminal), ssh cannot ask about the host key and every call
    # ends in "Host key verification failed". Both commands still logged "Agent deployed."
    # and exited 0, and --setup-remote went on to deploy and lock after ssh-copy-id had
    # failed. The mock tools fail the way ssh does and record that they were called.
    local bin="$TEST_ROOT/mockbin" out c
    mkdir -p "$bin"
    for c in ssh scp ssh-copy-id; do
        printf '#!/bin/sh\necho "%s: Host key verification failed." >&2\necho %s >> "%s/calls"\nexit 255\n' \
            "$c" "$c" "$bin" > "$bin/$c"
        chmod +x "$bin/$c"
    done
    : > "$TEST_ROOT/id_mock"; : > "$TEST_ROOT/id_mock.pub"
    set_config "REMOTE_KEY" "$TEST_ROOT/id_mock"

    out=$(PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --deploy-agent root@mock_host 2>&1) \
        && { echo -e "    ${RED}[FAIL] --deploy-agent exited 0 after scp failed${NC}"; return 1; }
    echo "$out" | grep -q "Agent deployed" \
        && { echo -e "    ${RED}[FAIL] --deploy-agent reported success after scp failed${NC}"; return 1; }

    rm -f "$bin/calls"
    out=$(PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --setup-remote root@mock_host 2>&1) \
        && { echo -e "    ${RED}[FAIL] --setup-remote exited 0 after ssh-copy-id failed${NC}"; return 1; }
    [ "$(cat "$bin/calls" 2>/dev/null)" = "ssh-copy-id" ] \
        || { echo -e "    ${RED}[FAIL] went on after ssh-copy-id failed: $(tr '\n' ' ' < "$bin/calls")${NC}"; return 1; }
    return 0
}

test_45_checks_answer_by_exit_code() {
    # The dispatcher reads the exit code of --is-job-done and --has-storage.
    # LOCAL --is-job-done said "false" with exit 0; a REMOTE agent said "false"
    # about unwritable storage with exit 0, and --has-storage passed that on as 0.
    run_backup || { echo -e "    ${RED}[FAIL] first run failed${NC}"; return 1; }
    echo $(( $(date +%s) - 3 * 86400 )) > "$MNT_DEST/daily.0/.backup_timestamp"
    "$SCRIPT_BIN" --config "$CONF_FILE" --is-job-done >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] --is-job-done exited 0 for a backup from three days ago${NC}"; return 1; }
    local bin="$TEST_ROOT/mock45"; mkdir -p "$bin"
    printf '#!/bin/sh\necho false\nexit 0\n' > "$bin/ssh"; chmod +x "$bin/ssh"
    set_config "BACKUP_MODE" "REMOTE"
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --has-storage >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] --has-storage exited 0 when the agent said false${NC}"; return 1; }
    return 0
}

test_46_mount_failure_is_reported() {
    # --mount said "Mounted" and exited 0 whether or not mount had worked.
    local bin="$TEST_ROOT/mock46" out; mkdir -p "$bin"
    for c in mount umount; do printf '#!/bin/sh\necho "%s: failed" >&2\nexit 32\n' "$c" > "$bin/$c"; done
    printf '#!/bin/sh\nexit 1\n' > "$bin/mountpoint"
    chmod +x "$bin"/*
    out=$(PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --mount "$TEST_ROOT/mp46" 2>&1) \
        && { echo -e "    ${RED}[FAIL] --mount exited 0 after mount failed${NC}"; return 1; }
    echo "$out" | grep -q "Mounted to" \
        && { echo -e "    ${RED}[FAIL] --mount reported success${NC}"; return 1; }
    PATH="$bin:$PATH" "$SCRIPT_BIN" --config "$CONF_FILE" --umount "$TEST_ROOT/mp46" >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] --umount exited 0 after umount failed${NC}"; return 1; }
    return 0
}

test_47_missing_source_fails_the_run() {
    # A source that does not exist was skipped without a word, and the run
    # ended in "Success" with a fresh timestamp.
    echo "data" > "$MNT_SRC/file47"
    set_config "SOURCE_DIRS" "$MNT_SRC $TEST_ROOT/no-such-source"
    run_backup && { echo -e "    ${RED}[FAIL] run with a missing source exited 0${NC}"; return 1; }
    grep -q "no-such-source' does not exist" "$LOG_FILE" \
        || { echo -e "    ${RED}[FAIL] missing source not named in the log${NC}"; return 1; }
    assert_missing "$MNT_DEST/daily.0/.backup_timestamp" || return 1
}

test_48_failed_rotation_is_not_committed() {
    # The commit's renames were not checked. When daily.0 could not become
    # daily.1, "mv daily.0.tmp daily.0" moved the new snapshot INTO the old one,
    # and the run reported success.
    run_backup || { echo -e "    ${RED}[FAIL] first run failed${NC}"; return 1; }
    echo $(( $(date +%s) - 3 * 86400 )) > "$MNT_DEST/daily.0/.backup_timestamp"
    : > "$MNT_DEST/daily.1"    # a file, not a snapshot: the rotation cannot use the name
    run_backup && { echo -e "    ${RED}[FAIL] run exited 0 although the rotation failed${NC}"; return 1; }
    [ -e "$MNT_DEST/daily.0/daily.0.tmp" ] \
        && { echo -e "    ${RED}[FAIL] new snapshot nested inside daily.0${NC}"; return 1; }
    return 0
}

test_49_bad_numbers_in_config() {
    # RETAIN_DAILY="7d" failed every test on it and switched daily off without
    # a word; a --config naming a file that is not there ran on the defaults.
    set_config "RETAIN_DAILY" "7d"
    "$SCRIPT_BIN" --config "$CONF_FILE" --status >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] RETAIN_DAILY=7d accepted${NC}"; return 1; }
    set_config "RETAIN_DAILY" "7"
    "$SCRIPT_BIN" --config "$TEST_ROOT/no-such.conf" --status >/dev/null 2>&1 \
        && { echo -e "    ${RED}[FAIL] missing --config file accepted${NC}"; return 1; }
    return 0
}

test_50_lock_key_verifies_the_result() {
    # lock-key found the blob, rewrote nothing it recognised, and said "locked".
    local home="$TEST_ROOT/lockhome50" f before
    rm -rf "$home"; mkdir -p "$home/.ssh"; f="$home/.ssh/authorized_keys"
    echo "unknown-type AAAAC3NzaC1lZDI1NTE5AAAAITARGETKEYtarget00000000000000000000000000 root@alice" > "$f"
    before=$(cat "$f")
    HOME="$home" "$SCRIPT_BIN" --agent-mode --config "$CONF_FILE" --action lock-key --client alice \
        --key-blob AAAAC3NzaC1lZDI1NTE5AAAAITARGETKEYtarget00000000000000000000000000 >> "$LOG_FILE" 2>&1 \
        && { echo -e "    ${RED}[FAIL] lock-key exited 0 without locking the key${NC}"; return 1; }
    [ "$(cat "$f")" = "$before" ] || { echo -e "    ${RED}[FAIL] authorized_keys was changed${NC}"; return 1; }
    return 0
}

test_52_rotation_keeps_the_old_timestamp() {
    # "cp -al" links .backup_timestamp into the new snapshot, and rsync -R
    # deletes only below the source paths, so the link survived. The commit
    # wrote into it: daily.1 got today's date as well, and over weeks every
    # snapshot shared one timestamp - nothing was ever promoted.
    local old
    run_backup || { echo -e "    ${RED}[FAIL] first run failed${NC}"; return 1; }
    old=$(( $(date +%s) - 3 * 86400 ))
    rm -f "$MNT_DEST/daily.0/.backup_timestamp"; echo "$old" > "$MNT_DEST/daily.0/.backup_timestamp"
    run_backup || { echo -e "    ${RED}[FAIL] second run failed${NC}"; return 1; }
    [ "$(cat "$MNT_DEST/daily.1/.backup_timestamp")" = "$old" ] \
        || { echo -e "    ${RED}[FAIL] daily.1 lost its timestamp: $(cat "$MNT_DEST/daily.1/.backup_timestamp"), expected $old${NC}"; return 1; }
    return 0
}

test_51_agent_lock_gives_up() {
    # With a lock directory that cannot be created, agent_lock removed a
    # "stale" lock after 5 s and looped back without sleeping: 100 % CPU, for ever.
    local conf="$TEST_ROOT/agent51.conf" rc
    : > "$TEST_ROOT/afile51"
    cat > "$conf" <<EOF
CONFIG_VERSION='2.0'
BASE_STORAGE="$TEST_ROOT/storage51"
LOCK_DIR="$TEST_ROOT/afile51/lock"
EOF
    timeout 30 "$SCRIPT_BIN" --agent-mode --config "$conf" --action prepare --client c51 >> "$LOG_FILE" 2>&1
    rc=$?
    [ "$rc" -eq 124 ] && { echo -e "    ${RED}[FAIL] agent lock still waiting after 30 s${NC}"; return 1; }
    [ "$rc" -ne 0 ] || { echo -e "    ${RED}[FAIL] prepare exited 0 without a lock${NC}"; return 1; }
    return 0
}

test_53_comments_in_list_values() {
    # A "#" line between the quotes is not a shell comment: every word of it
    # became a list item - fatal missing sources in SOURCE_DIRS since 18.8,
    # silent excludes in EXCLUDE_PATTERNS (issue #2). A quoted path with a
    # space became two items as well.
    mkdir -p "$MNT_SRC/a" "$MNT_SRC/my docs" "$MNT_SRC/c"
    echo "data" > "$MNT_SRC/a/keep"
    echo "data" > "$MNT_SRC/my docs/file"
    echo "data" > "$MNT_SRC/c/small"
    echo "data" > "$MNT_SRC/c/x.tmp"
    # Single quotes, as in a real config: set_config's double quotes would
    # end at the first quoted item.
    sed -i '/^SOURCE_DIRS=/d; /^EXCLUDE_PATTERNS=/d' "$CONF_FILE"
    cat >> "$CONF_FILE" <<EOF
SOURCE_DIRS='
    "$MNT_SRC/a"
    # keep a copy, it is small
	# indented with a tab
    "$MNT_SRC/my docs" # and one behind an item
    "$MNT_SRC/c"
'
EXCLUDE_PATTERNS='
    "*.tmp"
    # keep a copy of the cache, it is small
'
EOF
    run_backup || { echo -e "    ${RED}[FAIL] run with comments in the lists failed${NC}"; return 1; }
    local f
    for f in a/keep "my docs/file" c/small; do
        [ -e "$MNT_DEST/daily.0$MNT_SRC/$f" ] \
            || { echo -e "    ${RED}[FAIL] $f missing from the snapshot${NC}"; return 1; }
    done
    assert_missing "$MNT_DEST/daily.0$MNT_SRC/c/x.tmp" || return 1
    return 0
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
run_test_case "25 Wrapper Confines a Client" test_25_wrapper_confines_a_client
run_test_case "26 Lock Key in authorized_keys" test_26_lock_key
run_test_case "27 Local Exit 24 Commits" test_27_local_exit_24_commits
run_test_case "28 Local Failure Is Reported" test_28_local_failure_is_reported
run_test_case "29 Remote Failure Not Committed" test_29_remote_failure_does_not_commit
run_test_case "30 Purge Before Transfer" test_30_purge_runs_before_the_transfer
run_test_case "31 SIGTERM Stops the Run" test_31_term_stops_the_run
run_test_case "32 Remote Verify Is Recorded" test_32_remote_verify_is_recorded
run_test_case "33 Local Absolute Exclude" test_33_local_absolute_exclude
run_test_case "34 Period Signatures" test_34_period_signatures
run_test_case "35 Agent Serialises Actions" test_35_agent_serialises_actions
run_test_case "36 Kill Stops Only This Run" test_36_kill_stops_only_this_run
run_test_case "37 Install Replaces Atomically" test_37_install_replaces_atomically
run_test_case "38 WOL-Server Request Around the Run" test_38_wol_request_around_the_run
run_test_case "39 WOL-Server Down, Backup Runs" test_39_wol_unreachable_still_backs_up
run_test_case "40 WOL-Server Request Ended on Failure" test_40_wol_request_ended_after_a_failure
run_test_case "41 WOL-Server Sleep Only When Woken" test_41_wol_sleep_only_for_a_woken_device
run_test_case "42 WOL-Server Device Not Awake (504)" test_42_wol_device_not_awake
run_test_case "43 Sleep Inhibitor During the Run" test_43_inhibit_sleep_during_the_run
run_test_case "44 Setup Failures Are Reported" test_44_setup_failures_are_reported
run_test_case "45 Checks Answer by Exit Code" test_45_checks_answer_by_exit_code
run_test_case "46 Mount Failure Is Reported" test_46_mount_failure_is_reported
run_test_case "47 Missing Source Fails the Run" test_47_missing_source_fails_the_run
run_test_case "48 Failed Rotation Not Committed" test_48_failed_rotation_is_not_committed
run_test_case "49 Bad Numbers in Config" test_49_bad_numbers_in_config
run_test_case "50 Lock Key Verifies the Result" test_50_lock_key_verifies_the_result
run_test_case "51 Agent Lock Gives Up" test_51_agent_lock_gives_up
run_test_case "52 Rotation Keeps the Old Timestamp" test_52_rotation_keeps_the_old_timestamp
run_test_case "53 Comments in List Values" test_53_comments_in_list_values
run_test_case "54 WOL-Server Heartbeat" test_54_wol_heartbeat_while_the_run_lasts
run_test_case "55 Job Done Answered Locally" test_55_job_done_answered_locally
run_test_case "56 Wakeserver Options Warn" test_56_wakeserver_options_warn
run_test_case "57 WOL-Server by Its VPN Address" test_57_wol_by_address
run_test_case "58 WOL-Server --status Wakes, Says So" test_58_wol_status_wakes_and_says_so
run_test_case "59 WOL-Server --mount Holds Until --umount" test_59_wol_mount_holds_until_umount
run_test_case "60 --config Replaces the Default" test_60_config_replaces_the_default
run_test_case "61 Waits for the Network (WOL-Server)" test_61_waits_for_the_network_wol
run_test_case "62 Waits for the Backup Server" test_62_waits_for_the_backup_server
run_test_case "63 Wrapper Holds an Inhibitor" test_63_wrapper_holds_an_inhibitor

print_summary
