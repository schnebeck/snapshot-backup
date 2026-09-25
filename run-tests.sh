#!/bin/bash
# file: run-tests.sh
# Test suite for snapshot-backup.sh v18.7

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

print_summary
