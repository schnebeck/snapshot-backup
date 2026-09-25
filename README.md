# snapshot-backup.sh - Intelligent Incremental Backup

⚠️ **STATUS: STABLE / PRODUCTION READY (v18.7)**

### ⚖️ DISCLAIMER / LIMITATION OF LIABILITY

> **THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.** This script executes critical system commands (`rm`, `mv`, `rsync`) with root privileges. While it includes extensive safety mechanisms (Integration Tests, Strict Mode, Atomic Updates), use it at your own risk. **Please test your restore procedure before relying on this backup!**

## 📖 About This Tool

***snapshot-backup.sh*** is a modern, POSIX-compliant shell script designed as a robust alternative to `rsnapshot`. It creates incremental backups using hardlinks to save space and manages history intelligently based on **calendar logic** rather than simple rotation counts.

It features a **Unified Core Logic** for:

- **Local Backups:** USB drives, NAS mounts, and internal disks.

- **Remote Backups:** Push via SSH (automatically deploys and manages its own agent on the server).

## ⚙️ System Requirements

- **Operating System:** Linux, BSD, macOS, or Embedded Systems (BusyBox/Synology).

- **Shell:** Standard POSIX `/bin/sh` compatible (Bash is **not** required).

- **Dependencies:**
  
  - *Essential:* `rsync`, `ssh` (OpenSSH), and standard coreutils (`cp`, `mv`, `rm`, `stat`).
  
  - *Recommended:* `logger` (for syslog integration), `notify-send` (for desktop notifications).

- **Compatibility:** The script is built for resilience. It automatically detects missing features on minimal systems (e.g., if the `timeout` command is unavailable) and degrades gracefully without crashing.

## 🌟 Core Concepts (Key Features)

### 1. Push-Agent Architecture (Remote Backups)

A local backup is better than no backup, but it does not protect against fire or theft. Off-site backups are essential.
Unlike traditional systems where a central server "pulls" data from clients (requiring the server to have root access to your laptop), **snapshot-backup.sh** uses a "Push" model.
The client connects to the server and starts a temporary, unprivileged agent. This agent manages the storage logic locally on the server. There is no background daemon waiting on the server; the client is in full control.

### 2. The "Base Retention Level"

The script supports five stacked **Retention Levels**:

1. `hourly`

2. `daily`

3. `weekly`

4. `monthly`

5. `yearly`

You define how many snapshots to keep for each level. Setting a level to `0` disables it.
The script automatically detects your shortest configured level (usually `daily`). The newest snapshot of this level (e.g., `daily.0`) is **protected**. It represents the state of the *last successful run*. It is never immediately promoted or rotated away, ensuring the admin always knows exactly where the most recent data is.

### 3. Calendar-Based Promotion

Backups are not copied; they are **promoted**.
The script distinguishes between a simple "Rotation" (shifting numbers) and a "Promotion" (moving up a level).
When the system detects that a backup represents the start of a new **Calendar Period** (e.g., a Monday for "Weekly", or the 1st day of the month for "Monthly"), that snapshot is moved directly from the Base Level to the higher level.

- **Benefit:** A specific snapshot physically exists in only *one* folder at a time. This eliminates duplicates and maximizes storage efficiency.

### 4. In-Place Updates (Smart Refresh)

If the backup runs multiple times within the same **Time Period** (e.g., a laptop backing up 5 times on the same day), the script detects that a backup for "today" already exists.
Instead of creating a redundant `daily.0` and rotating the previous one, it performs an **rsync update** into the existing folder.

- **Result:** A clean history (1 day = 1 snapshot), regardless of how often the script triggers.
- **Limit:** an in-place update that is interrupted leaves `daily.0` part old, part new, still carrying the timestamp of the earlier run that day. The next successful run brings it level. A rotation (`.0.tmp`) has no such window: an interrupted one is simply not committed.

### 5. Smart Purge (Disk Space Protection)

To prevent the backup drive from filling up completely, you can define a `SPACE_LOW_LIMIT_GB`. If the destination storage drops below this threshold, the script proactively deletes the oldest snapshots from the Base Retention Level *before* starting the new transfer. This ensures the process does not crash due to a full disk.

### 6. Self-Healing & Gap Closing

Before every run, the system checks the consistency of the backup chain. If a snapshot is manually deleted (e.g., `daily.2` is missing), the script automatically renames older snapshots (`daily.3` becomes `daily.2`) to close the gap. The sequence remains continuous.

## 🎯 Scope & Limitations (Intended Use)

This tool is designed for simplicity and robustness in trusted environments.

✅ **Perfect Implementation For:**

- **Homelabs / SOHO:** Backing up Laptops, Raspberry Pis, and Servers in a private LAN/VPN.

- **Trusted Networks:** Where clients are managed by the same administrator as the backup server.

- **"Road Warriors":** Laptops that connect sporadically via VPN or SSH.

❌ **NOT Designed For:**

- **Zero-Trust Environments:** Backing up untrusted third-party clients.

- **Public Internet:** Exposing the SSH backup port directly to the internet (please use a VPN like OpenVPN or WireGuard).

- **Multi-Tenant Hosting:** Where "Client A" must be mathematically prevented from accessing "Client B" even if they gain root access to the backup server.

*Reason: The "Push" architecture via rsync generally requires trusted access. For Zero-Trust, consider "Pull" architectures or encryption-at-rest tools like BorgBackup.*

## 🚀 Quick Start

### 1. Installation

Run this on the machine you want to back up (Client):

```
# 1. Copy the script
sudo mv -f snapshot-backup.sh /usr/local/sbin/snapshot-backup.sh
sudo chmod 700 /usr/local/sbin/snapshot-backup.sh
```

### 2. Configuration

Create `/etc/snapshot-backup.conf`. You can generate a template using `--show-config`.

**Example A: Local Backup (USB/NAS)**

```
CONFIG_VERSION="2.0"
BACKUP_MODE="LOCAL"
BACKUP_ROOT="/mnt/backup"

# Retention Settings (How many to keep?)
RETAIN_HOURLY=0   # Set >0 to make 'hourly' the Base Level
RETAIN_DAILY=7    # Standard Base Level
RETAIN_WEEKLY=4
RETAIN_MONTHLY=12
RETAIN_YEARLY=2

# Safety Features
SPACE_LOW_LIMIT_GB=50   # Trigger Smart Purge if free space < 50GB
SMART_PURGE_SLOTS=2     # Delete 2 oldest dailies to free up space

SOURCE_DIRS=' "/etc" "/home" '
EXCLUDE_PATTERNS=' "*.tmp" "Cache/" ".git/" '
ENABLE_NOTIFICATIONS=true
```

**Example B: Remote Backup (SSH)**

```
CONFIG_VERSION="2.0"
BACKUP_MODE="REMOTE"
CLIENT_NAME="my-laptop"   # Important: Unique ID for this machine
REMOTE_HOST="192.168.1.10"
REMOTE_USER="root"
REMOTE_PORT="22"
REMOTE_KEY="/root/.ssh/id_ed25519"

# ... Retention & Sources as above ...
```

*Only for Remote:* Run the setup wizard once to exchange keys and prepare the server:

```
sudo snapshot-backup.sh --setup-remote root@192.168.1.10
```

*Note: This command is idempotent. It installs/updates the agent on the server without creating unnecessary directories.*

## 🎮 Usage & Automation

The script is designed for automation but can be controlled manually.

| Command                                   | Description                                               |
| ----------------------------------------- | --------------------------------------------------------- |
| `sudo snapshot-backup.sh`                 | Starts the backup (runs Smart Logic).                     |
| `sudo snapshot-backup.sh --status`        | Shows a table of all snapshots & their age.               |
| `sudo snapshot-backup.sh --mount`         | Temporarily mounts the backup (Local or SSHFS).           |
| `sudo snapshot-backup.sh --verify`        | Forces a deep checksum verification (Bit-Rot protection). |
| `sudo snapshot-backup.sh --version`, `-v` | Show script version.                                      |

### Automation (Cron)

A single line handles all retention levels (Daily, Weekly, Monthly...):

```
# /etc/cron.d/snapshot-backup
# Run every day at 04:00
0 4 * * * root /usr/local/sbin/snapshot-backup.sh
```

### Automation (NetworkManager / Laptop)

Ideal for laptops: Starts backup automatically when home and on AC power.
Create `/etc/NetworkManager/dispatcher.d/99-backup`:

```
#!/bin/bash
INTERFACE="$1"
ACTION="$2"
MY_SSID="Home-WiFi"

if [ "$ACTION" = "up" ]; then
    CURRENT=$(nmcli -t -f GENERAL.CONNECTION dev show "$INTERFACE" | cut -d: -f2)
    if [ "$CURRENT" = "$MY_SSID" ] && on_ac_power; then
         /usr/local/sbin/snapshot-backup.sh &
    fi
fi
```
There is a much more sophisticated Network-Manager dispacher script in the repository.

## 📂 Restore

Since backups are standard file systems, you can use any file manager or `cp`.

**Local Restore:**

```
cp -a /mnt/backup/daily.0/home/user/file.txt ~/Desktop/
```

**Remote Restore (via Mount):**

```
# 1. Mount the remote storage locally
sudo snapshot-backup.sh --mount /tmp/restore_point

# 2. Copy files
cp -a /tmp/restore_point/daily.0/home/user/file.txt ~/

# 3. Unmount
sudo snapshot-backup.sh --umount /tmp/restore_point
```

## 🧠 Appendix: Deep Dive & Details

### A. Strict Side-Effect Isolation

The remote agent is designed to be "clean". Commands like `--version`, `--status`, or `--check-storage` do **not** create directories or modify the filesystem on the server. Storage folders are only initialized when a write operation (like `prepare` or `commit`) is explicitly requested.

### B. Why are snapshots missing from the Base Level?

You might notice that Monday backups are often missing from the `daily` folder. **Reason:** Monday is usually the start of a new week. The script detects this via "Calendar Promotion" and immediately moves that backup to `weekly.0`. It is not missing; it has simply been promoted to the next logical level.

### C. Road-Warrior Logic

If a laptop has been offline for 3 weeks:

1. The script runs.

2. It detects: "The last `weekly` snapshot is 3 weeks old."

3. The *new* backup is created and immediately cascades up the chain to fill the oldest missing gap in `weekly` or `monthly`.

### D. Desktop Notifications

The script automatically detects the currently logged-in GUI user and sends status notifications (`libnotify`), even if the script is running as root in the background. This can be disabled via `ENABLE_NOTIFICATIONS=false`.

### E. CLI Options Reference

**`--status`** Connects to the storage (local or remote) and displays a formatted table of all existing snapshots, their timestamps, and age. Also shows storage usage and mount status.

**`--config [FILE]`, `-c [FILE]`** Loads a custom configuration file instead of the default `/etc/snapshot-backup.conf`. Useful for managing multiple backup jobs or testing.

**`--version`, `-v`** Displays the current version of the script and exits.

**`--verify`** Forces a deep checksum verification (`rsync --checksum`) for this run. This reads every file on both source and destination to detect bit-rot or silent corruption. Significantly slower than standard metadata checks.

**`--mount [PATH]`** Mounts the backup storage to the specified `[PATH]` (or defaults to the configured `BACKUP_ROOT`).

- **Local Mode:** Performs a bind mount.

- **Remote Mode:** Uses `sshfs` to mount the remote storage locally. This needs sftp, which a key locked to the wrapper does not get unless its `authorized_keys` line says `--allow-mount` (section I).

**`--umount [PATH]`** Unmounts the backup storage from `[PATH]`. Safe wrapper around `umount` or `fusermount`.

**`--deploy-agent [TARGET]`** Manually deploys or updates the agent script on a remote host. `TARGET` is usually `user@host`. Useful for upgrading the agent without running the full setup wizard.

**`--setup-remote [TARGET]`** Interactive wizard that handles SSH key generation, key exchange (`ssh-copy-id`), and agent deployment to the remote server.

**`--upgrade [--check|--force]`** Fetches the published version over HTTPS and installs it, keeping the previous one as `snapshot-backup.sh.<old-version>`. With `--check` it only reports which version is available. It refuses while a backup is running, and refuses a download that carries no `SCRIPT_VERSION`, does not parse as shell, or does not contain this program — a captive portal or a truncated transfer must not end up in `/usr/local/sbin`. Set `UPGRADE_URL` to install from a fork.

What it does *not* do is verify authorship: HTTPS establishes that the file came from the host in the URL, not who put it there. There is no signature to check, so a compromised repository would install like any other update. That is why this is a command somebody types and never something that runs on its own. The agent on the backup server is a copy of the same file and is not updated by it — run `--deploy-agent` to bring it along.

**`--is-running`** Checks if a backup process is currently active. Returns exit code `0` if running, `1` if idle. Useful for monitoring scripts or status bars.

**`--is-job-done`** Checks if a valid backup for the current Base Interval (e.g., today for `daily`) already exists. Returns exit code `0` (true) if done, `1` (false) if a backup is needed.

**`--has-storage`** Checks if the backup storage is accessible and writable. Returns exit code `0` (true) on success, `1` (false) on failure.

**`--install [USER]`** Installs a convenience symlink (wrapper) to `/usr/local/bin/snapshot-backup` and ensures the script is executable.

**`--kill`, `-k`** Safely stops running backup processes. It attempts a SIGTERM first to allow cleanup, then force kills if necessary. Removes stale lock files.

**`--debug`** Enables verbose logging to stdout and the log file. Useful for troubleshooting connection or rsync issues.

**`--timeout [SEC]`** Sets a custom timeout for network operations and checks. Overrides the default `NETWORK_TIMEOUT` (10s).

### E2. Hooks

Three commands the script calls at points only it knows. They are **called, not listened to**: the script waits for each and reads its exit code, so a `PRE` hook that fails stops the run.

| Setting | When | On failure |
|---|---|---|
| `PRE_RUN_CMD` | after the lock is held, before anything else | run aborts |
| `PRE_RSYNC_CMD` | after the target is prepared, before the first file is read | run aborts |
| `POST_RUN_CMD` | always — success, failure, abort, signal | logged only |

`POST_RUN_CMD` receives the run's exit code as `$1`. It lives in the cleanup path, which is the only place guaranteed to run on every exit — that matters when the `PRE` hook set something up that has to be taken down again.

The case this exists for:

```sh
PRE_RSYNC_CMD="/usr/local/sbin/freeze-and-snapshot.sh create"
POST_RUN_CMD="/usr/local/sbin/freeze-and-snapshot.sh remove"
```

A snapshot that was not created must not be backed up as though it had been; the copy would look consistent and would not be. And a guest left frozen because a backup died at 04:00 stays frozen until somebody notices — hence the teardown in cleanup rather than at the end of the happy path.

`PRE_RSYNC_CMD` runs **after** the rotation rather than before it, because on a large chain the hardlink copy takes minutes and a snapshot held open that long fills its copy-on-write area for nothing.

A hook whose failure should not matter says so in ordinary shell, which needs no special syntax:

```sh
PRE_RUN_CMD="/usr/local/sbin/dump-databases.sh || true"
```

One edge: if `PRE_RSYNC_CMD` fails during the **very first** run of a new client, the prepared — and empty — `daily.0` stays behind. It carries no timestamp, so the next run treats it as ancient and rotates it away. An existing chain is untouched, because that run updates in place and nothing was created.

### F. Configuration Reference

**`BACKUP_MODE`** (Default: `LOCAL`)
Defines the operation mode. `LOCAL` for direct disk access, `REMOTE` for SSH push.

**`BACKUP_ROOT`** (Default: `/mnt/backup`)

- **Local:** The directory where snapshots are stored.

- **Remote:** Used only as a default mountpoint for `--mount`.

**`CLIENT_NAME`** (Default: `hostname`)
Unique identifier for this machine. On the remote server, backups are stored in `$REMOTE_STORAGE_ROOT/$CLIENT_NAME`.

**`REMOTE_USER`** (Default: `root`)
SSH username for connecting to the backup server.

**`REMOTE_HOST`** (Default: `backup.server.local`)
Hostname or IP address of the backup server.

**`REMOTE_PORT`** (Default: `22`)
SSH port of the backup server.

**`REMOTE_KEY`** (Default: `/root/.ssh/id_ed25519`)
Path to the private SSH key used for authentication.

**`REMOTE_STORAGE_ROOT`** (Default: `/var/backups/snapshots`)
Absolute path on the *remote server* where all client backups are stored.

**`RETAIN_HOURLY`** (Default: `0`)
Number of hourly snapshots to keep. Set > 0 to enable hourly backups as the Base Level.

**`RETAIN_DAILY`** (Default: `7`)
Number of daily snapshots to keep. Usually the Base Level.

**`RETAIN_WEEKLY`** (Default: `4`)
Number of weekly snapshots (promoted from daily).

**`RETAIN_MONTHLY`** (Default: `12`)
Number of monthly snapshots (promoted from weekly).

**`RETAIN_YEARLY`** (Default: `0`)
Number of yearly snapshots (promoted from monthly).

**`SOURCE_DIRS`** (Default: `/`)
Space-separated list of local directories to back up. Example: `"/etc" "/home"`.

**`EXCLUDE_PATTERNS`** (Default: `.cache *.tmp ...`)
Space-separated list of file/folder patterns to exclude from rsync.

**`EXCLUDE_MOUNTPOINTS`** (Default: `/proc /sys /dev ...`)
Mount points whose directory must exist in every snapshot, even when nothing is mounted there at backup time — so a restored system has `/proc`, `/dev` or `/mnt/data` to mount onto. The list does **not** exclude anything: the contents of another filesystem stay out because rsync runs with `-x`. A directory on the same filesystem listed here is copied like any other; to keep something out, use `EXCLUDE_PATTERNS`.

**`SPACE_LOW_LIMIT_GB`** (Default: `0`)
Minimum free space (in GB) required on the target. If free space is below this limit, the oldest snapshots of the base interval are purged *before* the transfer — in LOCAL mode by the client, in REMOTE mode by the agent during `prepare`. After a successful backup the daily retention is additionally lowered by `SMART_PURGE_SLOTS` while space stays low. `0` disables this feature.

**`SMART_PURGE_SLOTS`** (Default: `0`)
How many of the oldest base snapshots may be deleted before a transfer when `SPACE_LOW_LIMIT_GB` is reached. Only the base interval is touched, and never its `.0` — weekly and monthly history is not traded for space automatically. If space is still short afterwards, the run proceeds and fails loudly rather than purging further.

**`DEEP_VERIFY_INTERVAL_DAYS`** (Default: `35`)
Automatically force a `--verify` run every N days to detect bit-rot.

**`ENABLE_NOTIFICATIONS`** (Default: `true`)
Send desktop notifications via `libnotify`.

**`NETWORK_TIMEOUT`** (Default: `10`)
Timeout in seconds for SSH connection tests and status checks.

**`RSYNC_EXTRA_OPTS`** (Default: empty)
Additional flags to pass directly to the `rsync` command.

###The client connects to the server and starts a temporary, unprivileged agent. 

### G. Agent Configuration (Server-Side)

When running in Agent Mode (on the backup server), the script optionally reads `/etc/snapshot-agent.conf`. This file is not created by default but can be used to override server-side defaults.

**Key Variables:**

- `BASE_STORAGE_PATH`: (Default: `/var/backups/snapshots`) The root directory where all client backups are stored.

- `AGENT_LOCK_DIR`: (Default: `/var/run/snapshot-agent`) Directory for lock files to prevent concurrent access to the same client store.

**Example `/etc/snapshot-agent.conf`:**

```
CONFIG_VERSION="2.0"
BASE_STORAGE_PATH="/mnt/bigraid/backups"
```

### H. Root Requirement & Security Trade-Off

This tool is designed for **System Backups**, which inherently requires root privileges on both ends:

1. **Client:** To read all files (e.g., `/etc/shadow`, `/home/*`) and preserve their ownership/permission attributes.

2. **Server:** To write those files and `chown` them to their original users (UIDs/GIDs).

**Security Implication:** Since the backup process requires a root SSH connection (albeit wrapped), a compromised client technically possesses elevated privileges on the backup server (via rsync).

**Mitigation Strategies:**

- **Trusted Networks (Primary Defense):** Use this tool only in LANs or VPNs where you trust the clients. It is not designed for Zero-Trust environments.

- **Security Wrapper (Logical Defense):** Use the wrapper (`snapshot-wrapper.sh`) to restrict SSH keys to specific commands. This prevents interactive logins.

- **Dedicated User (Defense in Depth):** Advanced users can configure a dedicated backup user on the server (manual setup required).
  
  - Create user: `useradd -m backup`
  
  - Configure `sudo` to allow the backup user to run the agent/rsync as root.
  
  - *Limitation:* Even with a dedicated user, sudo access for rsync is effectively root file access. This adds a layer of defense (no direct root login), but does NOT sandbox the file system access.

### I. The Security Wrapper

`--setup-remote` installs the client's key and then **locks it** to the wrapper for that one client (since 18.7; before, the key stayed unrestricted — root on the server for anyone holding it). The line in `authorized_keys` reads:

`command="/usr/local/bin/snapshot-wrapper.sh CLIENT",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...`

The wrapper (`snapshot-wrapper.sh`, generated by `--install`, plain POSIX `sh` so that it also runs on busybox machines) confines the key to **CLIENT**:

- **Agent:** only `prepare`, `commit`, `purge`, `status`, `check-storage`, `check-job-done` with `--client CLIENT`, plus `version`. Refused: `install`, any other client, and **`--config`** — the agent sources that file as shell code, so a client that uploaded one could have run anything as root.
- **rsync:** only as a server, only below `BASE_STORAGE_PATH/CLIENT` (resolved through symlinks, so a link a client planted in its own tree does not lead out of it), only with known options. Refused among others: protect-args (`-s`, it would hide the paths from the check), `-K`/`-L`/`-k` (follow links out of the tree), `--log-file`, `--temp-dir`, a `--link-dest` into another client.
- **sftp** (`--mount`): **not by default.** `sftp-server` cannot be confined — `-R -d` means read-only and a starting directory, not a jail — so it reads the whole server as root, other clients' backups and `/etc/shadow` included. A key that needs `--mount` gets it explicitly, knowing what it grants: `command="/usr/local/bin/snapshot-wrapper.sh CLIENT --allow-mount",…`. Real confinement would take a server-side `ChrootDirectory` in `sshd_config`, which a forced command cannot provide.
- anything else, interactive logins included: refused, and logged with `logger -t snapshot-wrapper`.

Consequently a client key can no longer **deploy** the agent (`--deploy-agent`, `--setup-remote` on an already locked key): installing the agent means writing code that runs as root, which is an administrator's job on the server itself (`snapshot-backup.sh --upgrade`, then `--install` there).

**Moving existing servers over.** A line **without** a client name keeps the old behaviour and logs `unpinned` — nothing breaks on upgrade. Add the client name to each line to confine it. `ENFORCE="0"` at the top of the wrapper logs what would be refused (`DENY … / AUDIT …`) but lets it through the old way: run a few nights like that, check `journalctl -t snapshot-wrapper`, then set `ENFORCE="1"`.

**What it does not do:** a confined client can still damage its **own** history — `--delete` into its own slot, a `purge` with low retention values. What protects against a client taken over by someone who encrypts it is a copy of the backup server that no client key reaches.

---

## 📆 Version History
- **v18.7:** A failed backup is a failed backup, in both modes. Three faults together let a LOCAL target sit full for eight months with every nightly run failing and nobody told:
  - The smart purge ran only after a *successful* backup. A full target makes the transfer fail, so the purge that would have made room never ran. It now runs before the transfer, as this README always said — in REMOTE mode inside the agent's `prepare`, which is now told `--smart-purge-slots` (the agent reads no config, so remote smart purge had been a no-op).
  - A failed LOCAL run logged `Backup failed` and returned normally: exit 0 for cron and systemd, `0` for `POST_RUN_CMD`. It now exits 1.
  - A failed REMOTE transfer was committed anyway, which writes the timestamp and turns a half-copied tree into something indistinguishable from a good snapshot. It is now not committed; the last complete snapshot stays as it is.

  rsync exit 24 (files vanished while being read) now counts as success in both modes — LOCAL treated it as a failure and never committed a live system with a busy log directory. An rsync whose exit status was never recorded (its subshell killed) counts as a failure; it used to count as success.

  More that failed quietly:
  - **A signal did not end the run.** The trap on INT/TERM cleaned up and returned, and the shell carried on — dash, busybox and bash alike: lock released, `POST_RUN_CMD` run mid-backup, then commit and exit 0. A signal now ends the run (129/130/143) and says so in the log.
  - **`--kill`** ran `pkill -f snapshot-backup.sh` — every process mentioning the script, runs of other configs and itself included — while the rsync of the run it meant kept going. It now stops the PID in this config's `PIDFILE` and the processes below it, waits for them, and clears a stale lock.
  - **REMOTE mode verified every night.** Only LOCAL wrote `last_verify.timestamp`; a REMOTE client counted from 1970 and ran `--checksum` over everything on both sides nightly. `DEEP_VERIFY_INTERVAL_DAYS` now applies to both.
  - **Absolute excludes did nothing in LOCAL mode** for any source but `/`: it copied `src/` into `dest/src/`, which anchors patterns at the source directory. LOCAL now copies with `-R` like REMOTE — same tree on disk, and a pattern like `/var/lib/plocate/*` means the real path in both modes.
  - **Weekly signatures** were `%Y%m%V`: a week across a month boundary got two weekly snapshots, and after ISO week 53 in early January no weekly was promoted until February. Weekly is now ISO year + week (`%G%V`), daily `%Y%m%d`, hourly `%Y%m%d%H`.
  - **The agent's lock was never read.** `prepare`, `commit` and `purge` for one client are now serialised; a lock whose holder is gone is removed, and `AGENT_LOCK_WAIT` (120 s) bounds the wait.
  - **sftp is off for locked keys** unless `--allow-mount` is given (section I): read-only turned out not to mean confined.
  - **`--install` rewrote the agent in place.** A shell reads its script piece by piece, so an agent action still running for another client would have continued in a mixture of two versions. The new agent is now moved into place as a new file.

  Upgrading: the snapshot tree is unchanged in both modes, so an existing chain is continued with its hardlinks — tested from 18.6 for LOCAL with `/` and with a second filesystem, and for REMOTE with 18.2, 18.6 and 18.7 clients against the new agent and wrapper.

  The wrapper confines a key to one client (section I). Before, it received the client name and ignored it: any agent arguments, any command starting with `rsync` and a full `sftp-server` went through as root, so one client's key could delete every other client's backups — or pass `--config` and have the agent source a file it had just uploaded. `--setup-remote` now locks the key it installed (the README had promised that since 15.1; nothing wrote it). Old `authorized_keys` lines without a client name keep working; `ENFORCE="0"` in the wrapper audits before it refuses.

  Test 25 as first written passed its arguments one position off in the refusal cases, so every one of them tested an empty command, which is refused anyway; it now tests what it names.

  Two long-standing test faults surfaced on the way. Test 24 sourced the whole script, whose `exit` ended the runner — from 18.6 on no test after it ran in a full run, and there was no summary. Test 21 wrote `POST_RUN_CMD` in double quotes, where loading the config expands `$1` to the config's own path; the template now says to use single quotes for hooks that read `$1`.

- **v18.6:** Hooks (`PRE_RUN_CMD`, `PRE_RSYNC_CMD`, `POST_RUN_CMD`) and `--upgrade`. Section E2 covers what the hooks are for and why `POST_RUN_CMD` lives in the cleanup path.

  Two details in here exist because the obvious version of them was wrong. `--upgrade` compares versions **numerically**, not for inequality: a check that only asks "is it different" installs an older file just as eagerly as a newer one, and `raw.githubusercontent.com` serves a cached copy for minutes after a push — enough to downgrade a machine by one version. `18.10` is newer than `18.9`, which a string comparison gets wrong as soon as the minor number passes nine. And the test suite now feeds the output of `--show-config` back through `sh -n`: the template is a heredoc, so a `$1` in a comment was expanded and aborted the whole command under `set -u`, unnoticed because a generated config had never been read back — which is the only thing it is for.

- **v18.5:** Rsync log classification no longer reports file names as errors. The patterns were unanchored, so any listed path containing `denied`, `failed:` or `fatal:` was logged as an error — a successful backup of a source holding `AccessDeniedException.php` produced hundreds of them, which is how people learn to stop reading the log. Anchored now, with `IO error` added because rsync writes that one unprefixed. `rsync warning: … vanished` stays unflagged: files disappearing while a live filesystem is copied is normal.

- **v18.4:** `LOCK_DIR` now follows a `PIDFILE` set in the config. It is derived when the script loads, before any config is read, so a host running two instances with separate PIDFILEs used to share the default lock — the second instance refusing to start for a reason its PID file did not explain. A config may still set `LOCK_DIR` explicitly; it is only re-derived when it does not.


- **v18.3:** Fix: Desktop notifications now work correctly when backup runs as root.
  - `runuser` (with `env DBUS_SESSION_BUS_ADDRESS=...`) replaces broken `sudo -E` approach.
  - `loginctl show-session -p Type` filters graphical sessions (x11/wayland) from SSH/tty-only sessions — notifications are silently skipped on pure server backups.
  - Lingering D-Bus sessions (systemd `linger` enabled) are handled correctly.
  - Fix: `su` fallback argument order corrected for busybox/Alpine compatibility.
  - Fix: Two bugs in test-framework.sh (wrong SSH key variable name, double failure counter).

- **v18.2:** Fix: Strict Side-Effect Isolation (prevents folder creation on non-write actions).
  
  - Fix: Wrapper logic alignment.
  
  - New: `--timeout` configuration and fallback handling.
  
  - New: Smart Purge logic for low disk space.
  
  - Changed: Removed short `-v` for verify (now `--version`).

- **v18.00:** Drop waterfall promotion for cleaner Calendar Logic. Complete rewrite of Test Framework.

- **v17.00:** Major Release. Unified Core Logic (Local/Remote parity). Robust Seeding of missing intervals. Recursive Calendar/Waterfall promotion. Strict integer sanitization.

- **v16.0:** Strict POSIX compliance refactoring. Configuration schema v2.0. Improved variable scoping.

- **v15.1:** Security & Usability Update. Added `--setup-remote` wizard with strict client-name checks and auto-hardening (SSH authorized_keys lock).

- **v15.0:** POSIX sh Rewrite. BusyBox capability (fallback for timeout/ACLs). Debug mode.

- **v14.1:** Integration Suite improvements.

- **v14.0:** Unified Client & Agent. Added self-deployment and help functionality.

- **v13.xx:** Legacy split-script architecture.

---

**License:** GPLv3 **Developed with:** ☕ and Shell-Love.
