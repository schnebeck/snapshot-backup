# snapshot-backup.sh - An Incremental Backup System

> **⚠️ STATUS: BETA / TESTING**
> This software is currently in a **Beta** state. While it has passed a comprehensive integration test suite, it should be tested thoroughly in your specific environment before being used for critical production backups. Use at your own risk.

## Overview

`snapshot-backup.sh` is a modern, Perl-free replacement for the `rsnapshot` backup system. It was developed extensively using **Gemini AI v3.0** within Google's Antigravity AI-enabled editor. Notably, version 15.0 marks the first fully **POSIX sh compliant** release, supporting generic Linux and BusyBox environments.

To mitigate validity issues common in AI development, the project relies on a comprehensive **Integration Test Suite** (`integration-test.sh`). This suite validates logic, error handling, and expected behavior at every step, ensuring a robust and reliable codebase. 

`snapshot-backup.sh` is a robust, incremental snapshot backup solution featuring waterfall rotation, atomic updates, and a unified agent architecture. It leverages **hardlinks** to ensure efficiency: snapshots share data for unchanged files, meaning a full file history is preserved while only occupying storage space for actual changes.

**Flexible Deployment:**

- **Local**: Back up directly to internal drives, USB storage, or mounted volumes (e.g., iSCSI).
- **Remote**: Use the embedded Agent to push/pull backups via SSH. This simplifies remote backups over VPNs or the internet, removing the need for complex networked storage protocols.  

## Key Features

- **Unified Architecture**: One script handles client orchestration and server-side agent duties.
- **Waterfall Rotation**: Implements a cascading retention policy. When a new backup is created, older backups are promoted down the chain (Hourly -> Daily -> Weekly -> Monthly -> Yearly) to maintain history efficiently.
- **Calendar-Based Promotion ("Road Warrior" Logic)**: The system recalculates promotion eligibility on every run based on the **timestamp of the snapshot**, not just the run time. 
    - *Example*: If a laptop backup runs once a month, the script correctly recognizes that a "Weekly" and "Monthly" promotion is due, even if 30 days have passed since the last run. This ensures gaps are handled gracefully and history is strictly preserved according to actual dates.
- **Single Trigger Logic**: Unlike `rsnapshot` which requires separate entries for each interval, this script requires only **one** generic trigger (e.g. Cron, Systemd Timer, or Network Dispatcher). It intelligently evaluates all rotation and promotion rules on every single run.
- **Atomic Updates**: Backups are first created in a temporary directory (`.tmp`). Only after a successful transfer are they moved to their final name. This guarantees that you never have broken or incomplete snapshots in your history.
- **Smart Purge**: Automatically reduces retention depth if storage space falls below a defined threshold.
- **Remote & Local**: Supports checking backing up local directories or pushing/pulling to remote servers via SSH.
- **Self-Deployment**: Can install itself to remote agents with a single command.
- **Parallel Agent Support**: Automatically segregates log files (`snapshot-backup-CLIENT.log`) and syslog tags based on client name, ensuring clean logs even when multiple agents run simultaneously.

## Requirements

### Client (The machine running the backup job)
- **OS**: Linux / Unix-like / BusyBox (Embedded Systems)
- **Shell**: POSIX `sh` compatible (Bash is NOT required).
- **Dependencies**: 
    - Essential: `rsync`, `ssh`
    - Recommended: `logger` (for syslog), `notify-send` (for desktop notifications)
    - Fallbacks: Script automatically handles missing `timeout` command on minimal systems.
- **Access**: SSH access to the backup server (if remote).

### Server (The machine validating/storing backups)
- **OS**: Linux / Unix-like
- **Dependencies**: `rsync`, `bash` (v4+), `logger`, `openssh-server`, `sftp-server`
- **User**: Dedicated backup user (recommended) or root.

## Installation

### Manual Installation
Copy the script to your system path:

```bash
sudo cp snapshot-backup.sh /usr/local/sbin/snapshot-backup.sh
sudo chmod 700 /usr/local/sbin/snapshot-backup.sh
```

### Remote Agent Deployment

#### Prerequisites: SSH Keys
The backup process is non-interactive. You must set up SSH Key authentication first:

```bash
# Syntax: ssh-keygen -t [TYPE]
ssh-keygen -t ed25519

# Syntax: ssh-copy-id [USER]@[HOST]
ssh-copy-id root@backup-server.local
```

#### Deploy Agent
To install the agent on a remote server:

```bash
# Syntax: snapshot-backup.sh --deploy-agent [USER]@[HOST]
sudo snapshot-backup.sh --deploy-agent root@backup-server.local
```
This will:

1. Copy the script to `/usr/local/sbin/snapshot-agent.sh`.
2. Set permissions (`chmod 700`, `chown 0:0`).
3. Generate a security wrapper (`/usr/local/bin/snapshot-wrapper.sh`) restricting valid commands.

**Note:**

- **One-Time Server Setup:** You only need to run this command **once** (e.g. from your first client) to prepare the server. You do **NOT** need to run it for every client.
- **Connectivity Check:** However, running it again is safe and serves as an excellent test to verify your SSH key setup works correctly.

### Configuration

#### 1. General Settings

To see all available options and default values, run:

```bash
snapshot-backup.sh --show-config
```

#### 2. Client Configuration

Create a configuration file (e.g., `/etc/snapshot-backup.conf`) for the backup job:

```bash
# /etc/snapshot-backup.conf

# Storage Location (Local or Remote Path)
BACKUP_ROOT="/mnt/backup_drive"

# Backup Mode (LOCAL or REMOTE)
BACKUP_MODE="LOCAL"

# Retention Policy (How many snapshots to keep)
RETAIN_HOURLY=24
RETAIN_DAILY=7
RETAIN_WEEKLY=4
RETAIN_MONTHLY=12
RETAIN_YEARLY=5

# Smart Purge (Optional)
# Reduce retention if free space < 50GB
SMART_PURGE_LIMIT_GB=50

# Source Directories (What to back up)
SOURCE_DIRS=(
    "/etc"
    "/home"
    "/var/www"
)

# Excludes (Rsync patterns)
EXCLUDE_PATTERNS=(
    "*.tmp"
    "*.iso"
    ".cachev/"
    "Downloads/"
)
```

#### 3. Agent Configuration

The agent (remote side) also uses a configuration file, typically located at `/etc/snapshot-agent.conf` on the remote server. This allows you to override storage paths or retention policies specifically for the agent.

**Note:** This configuration is **client-agnostic**. You only need one file for all incoming clients. The agent automatically creates subdirectories for each client based on the `CLIENT_NAME` variable defined in the **Client's** configuration (e.g. `CLIENT_NAME="my-laptop"` becomes `/var/backups/snapshots/my-laptop`).

```bash
# /etc/snapshot-agent.conf on Remote Server

# Override storage root for this agent
BASE_STORAGE="/var/backups/snapshots"
```

#### 4. Automatic Log Segregation & Syslog
The Agent (v15.0+) is designed for high-concurrency environments.
- **File Logging**: If the default log path (`/var/log/snapshot-backup.log`) is used, the Agent automatically redirects its output to `/var/log/snapshot-backup-<CLIENT_NAME>.log`. This ensures that logs from different clients are kept in separate files on the server.
- **Syslog Tagging**: All syslog messages are tagged with `snapshot-backup-<CLIENT_NAME>`, allowing you to filter logs easily using `journalctl -t snapshot-backup-<CLIENT_NAME>`.

No manual configuration is required for this feature; it activates automatically based on the Client Name.

## Usage

### 1. Best Practices & Filesystem Boundaries
The script **mandatorily** uses `rsync -x` (`--one-file-system`). This means rsync will count the "borders" of your filesystems but not cross them.

**Effect on Mount Points:**
- If you back up `/`, and `/boot` is a separate partition, the backup will contain an empty `/boot` directory.
- This is a **feature**: It preserves your full directory structure so you can simply mount file systems into these empty folders during a restore.

**From `fstab` to Config:**
For a restore-friendly setup, look at your `/etc/fstab` and add every real partition (ext4, xfs) to `SOURCE_DIRS`.

*Example Fstab:*
```text
/dev/sda1  /      ext4 ...
/dev/sda2  /home  ext4 ...
```

*Matching Backup Config:*
```bash
SOURCE_DIRS=(
    "/"
    "/home"
)
```
*Note: Because of `-x`, backing up `/` will NOT duplicate `/home` content, even though `/home` is technically inside `/`.*

### 2. Running Backups
The script is designed to be run by the `root` user (or a privileged backup user) via Cron or a Systemd Timer.

#### Manual Run (Testing)
To verify the configuration and run an immediate backup:

```bash
sudo snapshot-backup.sh --config /etc/snapshot-backup.conf
```

#### Automation (Cron)
Add a job to `/etc/crontab` to run hourly. 
**Migration Note**: Unlike rsnapshot, do NOT add separate lines for daily/weekly/etc. One line handles everything!

```bash
# Run backup at minute 0 of every hour
0 * * * * root /usr/local/sbin/snapshot-backup.sh --config /etc/snapshot-backup.conf
```
*Note: The script's locking mechanism prevents overlapping runs.*

### 3. Monitoring & Status
You can check the current status of snapshots (local or remote) at any time. This command is safe to run and does not interfere with active backups.

```bash
sudo snapshot-backup.sh --status
```
*Output includes: Process state, Storage usage, and a list of all snapshots per interval.*

### 4. Integrity Check (`--verify`)
By default, the backup script relies on file size and modification time to detect changes (standard rsync behavior). 
However, "Bit Rot" or silent filesystem corruption can go unnoticed. 

The `--verify` flag forces a **full checksum calculation** of all files in the base snapshot.

- **Why it's important:** It ensures that the file content on the disk exactly matches your source, detecting corruption that metadata checks might miss.
- **Can I skip it?** Yes, for daily runs. It is very I/O intensive and slow.
- **Recommendation:** Run it once a week or once a month.

- **Recommendation:** Run it once a week or once a month.

**Automatic "Road Warrior" Verification:**
You can configure `DEEP_VERIFY_INTERVAL_DAYS="35"` (Default: 35) in your config.
The script tracks the last successful verification timestamp locally. If more than 35 days have passed since the last verify, the next run will **automatically force a verification**, even if not explicitly requested. This ensures that laptops which miss their scheduled "1st of month" cron job will still be verified upon their next backup.
To disable, set `DEEP_VERIFY_INTERVAL_DAYS="0"`.

**Cron Example (Explicit Monthly Verify)**:

```bash
# Run a deep verification on the 1st of every month at 02:00
0 2 1 * * root /usr/local/sbin/snapshot-backup.sh --config /etc/snapshot-backup.conf --verify
```

**Scope & Feedback:**
- **Works safely** for both **Local** and **Remote** modes.
- **Positive Feedback (Exit Code 0):** The run was successful. If corruption was found, `rsync` **automatically healed** it by re-transferring the correct data from the source. Check the logs: if "Total transferred file size" is 0, your data was perfect. If > 0, changes (or corruption) were fixed.
- **Negative Feedback (Exit Code != 0):** A "Hard Failure" occurred (e.g. Disk could not be read, Network dropped). This requires manual intervention (Hardware check).

**Troubleshooting Verify Failure (Exit Code != 0):**
1. **Check Logs:** Look for I/O errors in `dmesg` or `/var/log/syslog`.
2. **Retry:** Run the command again to rule out transient network issues.

### 6. Restoration (Mounting & Recovery)
To restore individual files, you simply "mount" the backup directory.

- **Local Mode**: The directory is already accessible at `BACKUP_ROOT`.
- **Remote Mode**: You can mount the remote storage via SSHFS or simply browse via SFTP/SCP.

#### Full System Recovery
If you are restoring a full OS partition (e.g. from a Live USB), remember to verify `fstab` and recreate excluded system files.

**EXCLUDED FILES Checklist:**
If you used `EXCLUDE_PATTERNS` to save space (e.g. `swapfile`), the system may warn on boot ("Timed out waiting for device"). This is safe but annoying.
**Fix (Post-Restore):**

1. Boot into the system (Wait for timeout).
2. Recreate the Swapfile:

   ```bash
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```
3. Recreate missing empty directories (`/proc`, `/sys`) if they were not auto-created by the script's `EXCLUDE_MOUNTPOINTS` feature.

** Tip for Laptop Users:**
If you are on a laptop and checking backups remotely, you can use the status command to verify the last successful run. Since the script uses atomic commits, incomplete backups (e.g. if the laptop went to sleep) are held in a `.tmp` state and resumed automatically next time.

### 6. Desktop User Context
The core backup runs as `root` in the background. Desktop users do not have permission to modify or mount backups directly.

- **Notifications**: If enabled in config (`ENABLE_NOTIFICATIONS=true`), desktop users (logged into GUI) will receive pop-up notifications for defined events (Failures, Success, etc.).

### 7. Advanced: Debugging & Reference

#### Agent Mode (Direct Invocation)
The script automatically switches to Agent Mode when invoked as `snapshot-agent.sh` or with `--agent-mode`.
To see available agent commands:

```bash
/usr/local/sbin/snapshot-agent.sh --help
```

#### Wrapper Security Check
The installed wrapper restricts SSH commands to only allowed operations (`rsync`, checking status, agent logic).
To verify the wrapper:

```bash
/usr/local/bin/snapshot-wrapper.sh --help
```

## Security Considerations (Advanced)

### Why Root?
The default installation sets the agent script to `700` owned by `root:root`. This ensures that:

1. Only the highest-privilege user can modify execution logic.
2. The agent has unrestricted access to read/write all filesystem locations for backup.

### Risks
- **SSH Root Login**: Requires permitting root login over SSH (at least with keys).
- **Compromise**: If the client key is stolen, an attacker gains root access to the backup server.

### Hardening (Dedicated User)
To mitigate these risks, advanced users can configure a dedicated `backup` user:

1. Create user on server: `useradd -m backup`
2. Install agent manually using `chown backup:backup`.
3. Configure `sudo` to allow `backup` to run `rsync` or the agent script with privileges if needed (e.g. to preserve ownership of files).
4. **Warning**: This configuration is manual and not automated by the `--deploy-agent` command.

## Full Reference

### 1. Command Line Options (`snapshot-backup.sh`)
Usage: `snapshot-backup.sh [OPTIONS]`

### General

#### `--config`
*   **Function:** Load a specific configuration file instead of the default `/etc/snapshot-backup.conf`.
*   **Context:** local/remote
*   **Options:** `FILE` (Path to config)
*   **Example:** `snapshot-backup.sh --config /home/user/myconfig.conf`

#### `--show-config`
*   **Function:** Dump the currently loaded configuration and defaults to stdout. Useful for debugging or creating a new config file.
*   **Context:** local
*   **Example:** `snapshot-backup.sh --show-config > /etc/snapshot-backup.conf`

#### `--status`
*   **Function:** Show a summary of existing backup snapshots and storage usage.
*   **Context:** local/remote
*   **Example:** `snapshot-backup.sh --status`

#### `--debug`
*   **Function:** Enable verbose debug logging to console and logfile (includes full rsync file lists).
*   **Context:** local/remote
*   **Example:** `snapshot-backup.sh --debug`

#### `--help`, `-h`
*   **Function:** Show the help message and exit.

#### `--version`
*   **Function:** Show script version.

#### `--desktop`
*   **Function:** Send a desktop notification (via `notify-send`) with the current status. Useful for verifying notification setup.
*   **Context:** local
*   **Example:** `snapshot-backup.sh --desktop`

### Execution Control

#### `--force-weekly`, `-f`
*   **Function:** Force a weekly promotion run immediately, regardless of the current date.
*   **Context:** local/remote

#### `--force-monthly`, `-m`
*   **Function:** Force a monthly promotion run immediately.
*   **Context:** local/remote

#### `--force-yearly`, `-y`
*   **Function:** Force a yearly promotion run immediately.
*   **Context:** local/remote

#### `--verify`, `-v`
*   **Function:** Force a deep checksum verification relative to the previous snapshot.
*   **Context:** local/remote
*   **Note:** This is an expensive operation (reads all files). Defaults to metadata check (size/mtime) otherwise.

#### `--kill`, `-k`
*   **Function:** Kill any currently running backup process for this client (identified by lockfile).
*   **Context:** local
*   **Example:** `snapshot-backup.sh --kill`

#### `--timeout`
*   **Function:** Set network timeout in seconds for SSH/Rsync operations.
*   **Default:** `10`
*   **Example:** `snapshot-backup.sh --timeout 120`

#### `--service`, `-s`
*   **Function:** Force Service Mode. Logs are directed to the logfile/syslog instead of stdout, even if run interactively.
*   **Context:** local/remote

### Helpers & Status Checks

#### `--is-running`
*   **Function:** Check if a backup is currently running. Returns exit code 0 (True) if running, 1 (False) otherwise.
*   **Context:** local

#### `--is-job-done`
*   **Function:** Check if a valid backup already exists for the current interval (preventing duplicate runs).
*   **Context:** local/remote

#### `--has-storage`
*   **Function:** Check if the backup storage is reachable and writable.
*   **Context:** local/remote

### Deployment & Agent

#### `--deploy-agent`
*   **Function:** Deploy the script to a remote server setup. Copies the script and installs the wrapper.
*   **Context:** local (sending to remote)
*   **Options:** `[USER]@[HOST]`
*   **Example:** `snapshot-backup.sh --deploy-agent root@backup.local`

#### `--mount`
*   **Function:** Mount the backup directory to `/tmp/mnt_backup` (or custom path). Uses `mount --bind` for local and `sshfs` for remote.
*   **Context:** local/remote
*   **Options:** `[PATH]` (Optional target mountpoint), `--client [NAME]` (For remote mode)
*   **Example:** `snapshot-backup.sh --mount /mnt/restore`

#### `--umount`
*   **Function:** Unmount the backup directory.
*   **Context:** local/remote
*   **Options:** `[PATH]` (Optional argument to specify what to unmount)

#### `--agent-mode`
*   **Function:** Run in agent mode (server-side logic). Usually invoked automatically via SSH or symlink.
*   **Context:** remote (server-side)

---

### 2. Configuration Variables

#### 2a. Client Configuration (`/etc/snapshot-backup.conf`)

### Storage & Logic

#### `BACKUP_ROOT`
*   **Function:** Destination path for **LOCAL** mode. Ignored if `BACKUP_MODE="REMOTE"`.
*   **Default:** `/mnt/backup`
*   **Example:** `BACKUP_ROOT="/media/usb-drive/backups"`

#### `BACKUP_MODE`
*   **Function:** Defines operation mode.
*   **Options:** `LOCAL` (write to disk), `REMOTE` (SSH to agent)
*   **Default:** `LOCAL`

#### `CLIENT_NAME`
*   **Function:** Unique identifier for this client. Used for folder naming on the remote server.
*   **Default:** `hostname`

### Remote Connectivity

#### `REMOTE_HOST`
*   **Function:** IP or Hostname of the backup server.

#### `REMOTE_USER`
*   **Function:** SSH user for the backup server.
*   **Default:** `root`

#### `REMOTE_PORT`
*   **Function:** SSH port.
*   **Default:** `22`

#### `REMOTE_AGENT`
*   **Function:** Absolute path to the `snapshot-agent.sh` script on the remote server.
*   **Default:** `/usr/local/sbin/snapshot-agent.sh`

#### `SSH_KEY`
*   **Function:** Private key file for SSH authentication.
*   **Default:** `~/.ssh/id_ed25519`

### Retention Policy

#### `RETAIN_${INTERVAL}`
*   **Function:** Number of snapshots to keep for each interval.
*   **Variables:** `RETAIN_HOURLY`, `RETAIN_DAILY`, `RETAIN_WEEKLY`, `RETAIN_MONTHLY`, `RETAIN_YEARLY`
*   **Default:** Daily: 7, Weekly: 4, Monthly: 12, Yearly: 5

#### `DEEP_VERIFY_INTERVAL_DAYS`
*   **Function:** Interval in days to force a deep checksum verification. Supports "Road Warriors" by catching up on verification if machine was offline.
*   **Default:** `35` (Set to `0` to disable)

#### `SMART_PURGE_LIMIT_GB`
*   **Function:** Low disk space threshold (in GB). If free space is below this limit, retention is reduced.
*   **Default:** `0` (Disabled)

### Sources & Filters

#### `SOURCE_DIRS`
*   **Function:** Bash array of local directory paths to back up.
*   **Example:** `SOURCE_DIRS=("/etc" "/home" "/var/www")`

#### `EXCLUDE_PATTERNS`
*   **Function:** Bash array of rsync exclude patterns.
*   **Example:** `EXCLUDE_PATTERNS=("*.tmp" ".cache/")`

#### `EXCLUDE_MOUNTPOINTS`
*   **Function:** Bash array of mountpoints to exclude from content backup but **force creation** as empty directories.
*   **Example:** `EXCLUDE_MOUNTPOINTS=("/proc" "/sys" "/dev")`

### System Config

#### `LOGFILE`
*   **Function:** Path to the log file.
*   **Default:** `/var/log/snapshot-backup.log`

#### `PIDFILE`
*   **Function:** Path to the lock file. Prevents multiple backup instances from running simultaneously (which could corrupt data or thrash IO). The `--kill` command uses this file to identify the process ID of the running job.
*   **Default:** `/var/run/snapshot-backup.pid`

#### `ENABLE_NOTIFICATIONS`
*   **Function:** Send desktop notifications via `notify-send` for start/finish/error events.
*   **Options:** `true` / `false`
*   **Default:** `false`

#### `RSYNC_EXTRA_OPTS`
*   **Function:** Additional flags to pass directly to the `rsync` command.
*   **Example:** `RSYNC_EXTRA_OPTS="--bwlimit=1000"`

---

#### 2b. Agent Configuration (`/etc/snapshot-agent.conf`)

#### `BASE_STORAGE`
*   **Function:** **Overwrites the storage root.** Where the agent stores incoming backups on the server.
*   **Default:** `/var/backups/snapshots` (if not set)

#### `LOCK_DIR`
*   **Function:** Directory for lock files.
*   **Default:** `/var/run/snapshot-agent`

## Developer & Architecture Notes

### Unified Single-File Design
The project uses a single file `snapshot-backup.sh` to simplify distribution and versioning.
- **Client Logic**: Runs when executed as `snapshot-backup.sh`. Handles configuration, locking, and orchestration of `rsync`.
- **Agent Logic**: Runs when executed as `snapshot-agent.sh` (symlink) or with `--agent-mode`. Handles local filesystem operations on the server side (prepare, commit, purge).

### Remote Protocol (Command Pattern)
The Client does not run arbitrary commands on the server. Instead, it triggers specific **Actions** via SSH:
1. **Prepare**: Agent creates `<backup_root>/daily.0.tmp`.
2. **Transfer**: Client `rsync`s data directly into `daily.0.tmp`.
3. **Commit**: Agent rotates old snapshots and renames `.tmp` to `daily.0`.

### Testing
Use `integration-test.sh` for all changes. It creates a self-contained environment (no root needed for local tests) and verifies:
- Retention logic (waterfall).
- Error handling (locking, timeout).
- Remote simulation.

## Version History
- **v15.0**: POSIX sh Rewrite. BusyBox capability (fallback for timeout/ACLs). Debug mode.
- **v14.1**: Integration Suite improvements.
- **v14.0**: Unified Client & Agent. Added self-deployment and help functionality.
- **v13.xx**: Legacy split-script architecture.

## License
GPLv3
