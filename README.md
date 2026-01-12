# snapshot-backup.sh - Intelligent Incremental Backup

⚠️ **STATUS: STABLE / PRODUCTION READY (v18.2)**

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
sudo cp snapshot-backup.sh /usr/local/sbin/snapshot-backup.sh
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

- **Remote Mode:** Uses `sshfs` to mount the remote storage locally.

**`--umount [PATH]`** Unmounts the backup storage from `[PATH]`. Safe wrapper around `umount` or `fusermount`.

**`--deploy-agent [TARGET]`** Manually deploys or updates the agent script on a remote host. `TARGET` is usually `user@host`. Useful for upgrading the agent without running the full setup wizard.

**`--setup-remote [TARGET]`** Interactive wizard that handles SSH key generation, key exchange (`ssh-copy-id`), and agent deployment to the remote server.

**`--is-running`** Checks if a backup process is currently active. Returns exit code `0` if running, `1` if idle. Useful for monitoring scripts or status bars.

**`--is-job-done`** Checks if a valid backup for the current Base Interval (e.g., today for `daily`) already exists. Returns exit code `0` (true) if done, `1` (false) if a backup is needed.

**`--has-storage`** Checks if the backup storage is accessible and writable. Returns exit code `0` (true) on success, `1` (false) on failure.

**`--install [USER]`** Installs a convenience symlink (wrapper) to `/usr/local/bin/snapshot-backup` and ensures the script is executable.

**`--kill`, `-k`** Safely stops running backup processes. It attempts a SIGTERM first to allow cleanup, then force kills if necessary. Removes stale lock files.

**`--debug`** Enables verbose logging to stdout and the log file. Useful for troubleshooting connection or rsync issues.

**`--timeout [SEC]`** Sets a custom timeout for network operations and checks. Overrides the default `NETWORK_TIMEOUT` (10s).

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
List of paths to exclude to prevent recursion or backing up virtual filesystems.

**`SPACE_LOW_LIMIT_GB`** (Default: `0`)
Minimum free space (in GB) required on the target. If free space is below this limit, the oldest snapshots are purged *before* backup. `0` disables this feature.

**`SMART_PURGE_SLOTS`** (Default: `0`)
Number of oldest snapshots to delete when `SPACE_LOW_LIMIT_GB` is reached.

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

When `snapshot-backup.sh` installs itself on the server (via `--setup-remote`), it configures the SSH key to execute a **Wrapper Script** instead of a raw shell.

**How it works:** The `authorized_keys` file on the server will look like this: `command="/usr/local/bin/snapshot-wrapper.sh",no-port-forwarding,... ssh-ed25519 AAAA...`

The wrapper script (`snapshot-wrapper.sh`):

1. Intercepts the incoming SSH command.

2. **Validates** against a whitelist of allowed commands (e.g., `rsync`, `snapshot-agent.sh`).

3. **Blocks** dangerous commands (like `/bin/bash`, `rm -rf /`).

4. **Executes** the allowed command.

This ensures that even if the SSH key is leaked, an attacker cannot easily get a full root shell on the server, but is restricted to the backup functions.

---

## 📆 Version History

- **v18.2:** * Fix: Strict Side-Effect Isolation (prevents folder creation on non-write actions).
  
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
