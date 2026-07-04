# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all integration tests (requires root)
sudo bash run-tests.sh

# Run a single test by name fragment
sudo bash run-tests.sh "15"          # matches test_15_network_retry_logic
sudo bash run-tests.sh "Idempotency" # matches test_13 by display name

# Test output log
tail -f /tmp/snapshot-test-suite.log

# Install the script (client side)
sudo mv -f snapshot-backup.sh /usr/local/sbin/snapshot-backup.sh
sudo chmod 700 /usr/local/sbin/snapshot-backup.sh

# Deploy agent to a server
sudo snapshot-backup.sh --setup-remote root@192.168.1.10

# Generate a config template
sudo snapshot-backup.sh --show-config
```

## Architecture

### Dual-Mode Single File

`snapshot-backup.sh` is one file that acts as both **client** and **agent**. Mode is selected by:
- `--agent-mode` flag, or
- script being named/symlinked as `snapshot-agent.sh`

**Client** runs on the machine being backed up, reads `/etc/snapshot-backup.conf`, handles locking, notification, and orchestration.  
**Agent** runs on the backup server (called via SSH by the client), handles storage operations only. It responds to `--action prepare|commit|purge|status|check-storage|check-job-done`.

For remote backups the client does: `prepare` → rsync → `commit` → `purge`. Each is a separate SSH call.

### Snapshot Layout

Backups are stored as plain directories named `$INTERVAL.$INDEX`:
```
/mnt/backup/
  daily.0      ← most recent (protected, never immediately promoted)
  daily.1
  daily.6
  weekly.0
  monthly.0
```

Intervals in order: `hourly daily weekly monthly yearly`. The shortest interval with `RETAIN_*` > 0 is the **Base Interval** (detected by `detect_base_interval()`).

### Calendar Promotion

Snapshots are **moved** up the chain (never copied) when a new calendar period starts — a Monday triggers promotion to `weekly`, the 1st of the month to `monthly`. `get_sortable_date()` generates period signatures for comparison. Promotion uses `check_and_promote_single_item()` which enforces:
- Base `.0` is always protected (never source of promotion)
- "Last man standing" rule: don't promote if it would leave a level empty

### In-Place Updates

If a backup already exists for the current period (same calendar signature), rsync updates it directly rather than rotating. `core_prepare_backup_target()` decides: return `.0` for in-place, `.0.tmp` for new rotation. `core_commit_backup()` promotes `.tmp → .0` atomically via `mv`.

### Timestamps

Each snapshot directory contains `.backup_timestamp` (Unix epoch). Read via `read_timestamp()` which handles both epoch integers and legacy `YYYY-MM-DD HH:MM:SS` format.

### Locking

Exclusive lock via `mkdir "$LOCK_DIR"` (atomic on POSIX). PID written to `$PIDFILE`. `cleanup()` registered via `trap EXIT INT TERM`.

### Desktop Notifications

`notify()` runs in a subshell. When root, it finds the desktop user by scanning `/run/user/*/bus` sockets, filters via `_has_graphical_session()` (allows graphical sessions and lingering users, blocks SSH/tty-only server sessions), then uses `runuser` (or `su -c CMD USER` as fallback) with `DBUS_SESSION_BUS_ADDRESS` set explicitly.

## Key Conventions

- **POSIX sh** throughout — no bash arrays, no `[[`, no process substitution. The one deliberate deviation: `local` is used for variable scoping.
- **`sanitize_int()`** must be applied to all externally-derived integers before arithmetic use. It strips non-digits and returns `0` for empty input.
- **`safe_rm()`** wraps all `rm -rf` calls — refuses to act on `/` or empty paths.
- Config version is checked on load (`EXPECTED_CONFIG_VERSION="2.0"`); a mismatch is a hard error.
- Tests use `ENABLE_NOTIFICATIONS=false` in `$CONF_FILE` to suppress D-Bus calls.
- The test suite requires root (for `/var/run` access and lock simulation) and uses `/tmp/backup-tests/` as scratch space.
