# **snapshot-backup.sh \- An Incremental Backup System**

**⚠️ STATUS: STABLE / PRODUCTION READY**  
Version 17.00 markiert einen signifikanten Meilenstein in Stabilität und Logik-Konsistenz.

## **Overview**

snapshot-backup.sh is a modern, Perl-free replacement for the rsnapshot backup system. It was developed extensively using **Gemini AI** within Google's Antigravity AI-enabled editor. Notably, version 17.0 marks a mature **POSIX sh compliant** release, supporting generic Linux and BusyBox environments with a unified core logic.  
To mitigate validity issues common in AI development, the project relies on a comprehensive **Integration Test Suite** (integration-test.sh). This suite validates logic, error handling, and expected behavior at every step, ensuring a robust and reliable codebase.  
snapshot-backup.sh is a robust, incremental snapshot backup solution featuring waterfall rotation, atomic updates, and a unified agent architecture. It leverages **hardlinks** to ensure efficiency: snapshots share data for unchanged files, meaning a full file history is preserved while only occupying storage space for actual changes.  
**Flexible Deployment:**

* **Local**: Back up directly to internal drives, USB storage, or mounted volumes (e.g., iSCSI).  
* **Remote**: Use the embedded Agent to push/pull backups via SSH. This simplifies remote backups over VPNs or the internet, removing the need for complex networked storage protocols.

## **Key Features**

* **Unified Architecture**: One script handles client orchestration and server-side agent duties.  
* **Unified Core Logic**: Identical rotation and promotion logic for both Local and Remote modes ensures consistent behavior regardless of the target.  
* **Seeding & Healing**: Automatically fills gaps in the retention hierarchy (e.g., creating a missing .0 directory from the next available snapshot) during initialization.  
* **Waterfall Rotation**: Implements a cascading retention policy. When a new backup is created, older backups are promoted down the chain (Hourly \-\> Daily \-\> Weekly \-\> Monthly \-\> Yearly) to maintain history efficiently.  
* **Recursive Promotion**: Advanced logic ensures that snapshots ripple through the retention chain correctly in a single run if multiple promotions are due.  
* **Calendar-Based Promotion ("Road Warrior" Logic)**: The system recalculates promotion eligibility on every run based on the **timestamp of the snapshot**, not just the run time.  
  * *Example*: If a laptop backup runs once a month, the script correctly recognizes that a "Weekly" and "Monthly" promotion is due, even if 30 days have passed since the last run. This ensures gaps are handled gracefully and history is strictly preserved according to actual dates.  
* **Single Trigger Logic**: Unlike rsnapshot which requires separate entries for each interval, this script requires only **one** generic trigger (e.g. Cron, Systemd Timer, or Network Dispatcher). It intelligently evaluates all rotation and promotion rules on every single run.  
* **Atomic Updates**: Backups are first created in a temporary directory (.tmp). Only after a successful transfer are they moved to their final name. This guarantees that you never have broken or incomplete snapshots in your history.  
* **Smart Purge**: Automatically reduces retention depth if storage space falls below a defined threshold.  
* **Remote & Local**: Supports checking backing up local directories or pushing/pulling to remote servers via SSH.  
* **Self-Deployment**: Can install itself to remote agents with a single command.  
* **Parallel Agent Support**: Automatically segregates log files (snapshot-backup-CLIENT.log) and syslog tags based on client name, ensuring clean logs even when multiple agents run simultaneously.

## **Scope & Limitations (Intended Use)**

This tool is designed for **simplicity and robustness** in trusted environments.

### **✅ Perfect Implementation For:**

* **Homelabs / SOHO**: Backing up Laptops, Raspberry Pis, and Servers in a private LAN/VPN.  
* **Trusted Networks**: Where clients are managed by the same administrator as the backup server.  
* **"Road Warriors"**: Laptops that connect sporadically via VPN.

### **❌ NOT Designed For:**

* **Zero-Trust Environments**: Backing up untrusted third-party clients.  
* **Public Internet**: Exposing the SSH backup port directly to the internet (use a VPN\!).  
* **Multi-Tenant Hosting**: Where "Client A" must be mathematically prevented from hacking "Client B" even if they gain root on the backup server.

*Reason*: The "Push" architecture via rsync requires root access, which inherently implies trust. For Zero-Trust, look at "Pull" architectures or tools like BorgBackup.

## **Requirements**

### **Client (The machine running the backup job)**

* **OS**: Linux / Unix-like / BusyBox (Embedded Systems)  
* **Shell**: POSIX sh compatible (Bash is NOT required).  
* **Dependencies**:  
  * Essential: rsync, ssh  
  * Recommended: logger (for syslog), notify-send (for desktop notifications)  
  * Fallbacks: Script automatically handles missing timeout command on minimal systems.  
* **Access**: SSH access to the backup server (if remote).

### **Server (The machine validating/storing backups)**

* **OS**: Linux / Unix-like  
* **Dependencies**: rsync, bash (v4+), logger, openssh-server, sftp-server  
* **User**: Dedicated backup user (recommended) or root.

## **Installation & Configuration**

### **1\. Installation (Client)**

*Perform this on every machine you want to back up.*  
Copy the script to your system path and make it executable:  
sudo cp snapshot-backup.sh /usr/local/sbin/snapshot-backup.sh  
sudo chmod 700 /usr/local/sbin/snapshot-backup.sh

### **2\. Configuration**

**CRITICAL**: You must create a valid configuration file before proceeding.  
**Tip**: To see all available options and default values (useful for generating a initial config), run:  
snapshot-backup.sh \--show-config

#### **Option A: Local Backup (USB/NAS Mount)**

Template for local backups.  
Adapt BACKUP\_ROOT and SOURCE\_DIRS to your system.  
\# /etc/snapshot-backup.conf (Local Example)  
CONFIG\_VERSION="2.0"

BACKUP\_MODE="LOCAL"  
BACKUP\_ROOT="/mnt/external\_drive"

\# Retention: Keep 7 dailies, 4 weeklies...  
RETAIN\_HOURLY=0  
RETAIN\_DAILY=7  
RETAIN\_WEEKLY=4  
RETAIN\_MONTHLY=12  
RETAIN\_YEARLY=5

SOURCE\_DIRS='  
    "/etc"  
    "/home"  
    "/var/www"  
'

EXCLUDE\_PATTERNS='  
    "\*.tmp"  
    "\*.iso"  
    "Downloads/"  
'

#### **Option B: Remote Backup (over SSH)**

Template for remote backups.  
Adapt REMOTE\_HOST, SSH\_KEY, and CLIENT\_NAME to your environment.  
\# /etc/snapshot-backup.conf (Remote Example)  
CONFIG\_VERSION="2.0"

BACKUP\_MODE="REMOTE"

\# Remote Connection Details  
REMOTE\_USER="root"  
REMOTE\_HOST="backup.lan"  
REMOTE\_PORT="22"  
SSH\_KEY="/root/.ssh/id\_ed25519"

\# Unique ID for this machine (REQUIRED for Setup Wizard)  
CLIENT\_NAME="laptop-bedroom"

\# Retention  
RETAIN\_HOURLY=0   \# Laptops might skip hourly  
RETAIN\_DAILY=7  
RETAIN\_WEEKLY=4  
RETAIN\_MONTHLY=12  
RETAIN\_YEARLY=2

SOURCE\_DIRS='  
    "/etc"  
    "/home"  
'

EXCLUDE\_PATTERNS='  
    "\*.tmp"  
    "Cache/"  
'

### **3\. Remote Server Setup (Optional)**

*Perform this ONLY if you are backing up to a remote server.*  
Once your CLIENT\_NAME is configured (Step 2), use the wizard to prepare the server.

#### **Remote Agent Deployment (Wizard)**

**Recommended Method**: Use the built-in wizard.  
\# Syntax: snapshot-backup.sh \--setup-remote \[USER\]@\[HOST\]  
sudo ./snapshot-backup.sh \--setup-remote root@backup-server.local

**What this does:**

1. **Duplicate Check**: Verifies if CLIENT\_NAME conflicts with existing data.  
2. **SSH Check**: Checks/Generates SSH keys and copies them to the server (ssh-copy-id).  
3. **Deployment**: Installs the snapshot-agent.sh script on the server.  
4. **Auto-Hardening**: Locks the SSH key in authorized\_keys to this specific CLIENT\_NAME.

#### **Manual Remote Setup (Advanced)**

*For manual setups or scripts.*

1. **SSH Keys**:  
   ssh-keygen \-t ed25519  
   ssh-copy-id root@backup-server.local

2. **Install Agent**:  
   \# Legacy command for batch scripts  
   sudo ./snapshot-backup.sh \--deploy-agent root@backup-server.local

3. Security Hardening:  
   Edit /root/.ssh/authorized\_keys on the server manually:  
   command="/usr/local/bin/snapshot-wrapper.sh my-client-name" ssh-ed25519 ...

#### **3\. Agent Configuration (Optional)**

The agent (remote side) also uses a configuration file, typically located at /etc/snapshot-agent.conf. This allows you to override storage paths specifically for the server.  
**Note:** This file is **client-agnostic**. You only need one file for all incoming clients.  
\# /etc/snapshot-agent.conf on Remote Server

\# Override storage root for this agent  
BASE\_STORAGE="/var/backups/snapshots"

#### **4\. Automatic Log Segregation & Syslog**

The Agent (v15.0+) is designed for high-concurrency environments.

* **File Logging**: If the default log path (/var/log/snapshot-backup.log) is used, the Agent automatically redirects its output to /var/log/snapshot-backup-\<CLIENT\_NAME\>.log. This ensures that logs from different clients are kept in separate files on the server.  
* **Syslog Tagging**: All syslog messages are tagged with snapshot-backup-\<CLIENT\_NAME\>, allowing you to filter logs easily using journalctl \-t snapshot-backup-\<CLIENT\_NAME\>.

No manual configuration is required for this feature; it activates automatically based on the Client Name.

## **Usage**

### **1\. Best Practices & Filesystem Boundaries**

The script **mandatorily** uses rsync \-x (--one-file-system). This means rsync will count the "borders" of your filesystems but not cross them.  
**Effect on Mount Points:**

* If you back up /, and /boot is a separate partition, the backup will contain an empty /boot directory.  
* This is a **feature**: It preserves your full directory structure so you can simply mount file systems into these empty folders during a restore.

From fstab to Config:  
For a restore-friendly setup, look at your /etc/fstab and add every real partition (ext4, xfs) to SOURCE\_DIRS.  
*Example Fstab:*  
/dev/sda1  /      ext4 ...  
/dev/sda2  /home  ext4 ...

*Matching Backup Config:*  
SOURCE\_DIRS='  
    "/"  
    "/home"  
'

*Note: Because of \-x, backing up / will NOT duplicate /home content, even though /home is technically inside /.*

### **2\. Running Backups**

The script is designed to be run by the root user (or a privileged backup user) via Cron or a Systemd Timer.

#### **Manual Run (Testing)**

To verify the configuration and run an immediate backup:  
sudo snapshot-backup.sh \--config /etc/snapshot-backup.conf

#### **Automation (Cron)**

Add a job to /etc/crontab to run hourly.  
Migration Note: Unlike rsnapshot, do NOT add separate lines for daily/weekly/etc. One line handles everything\!  
\# Run backup at minute 0 of every hour  
0 \* \* \* \* root /usr/local/sbin/snapshot-backup.sh \--config /etc/snapshot-backup.conf

*Note: The script's locking mechanism prevents overlapping runs.*

### **3\. Monitoring & Status**

You can check the current status of snapshots (local or remote) at any time. This command is safe to run and does not interfere with active backups.  
sudo snapshot-backup.sh \--status

*Output includes: Process state, Storage usage, and a list of all snapshots per interval.*

### **4\. Integrity Check (--verify)**

By default, the backup script relies on file size and modification time to detect changes (standard rsync behavior).  
However, "Bit Rot" or silent filesystem corruption can go unnoticed.  
The \--verify flag forces a **full checksum calculation** of all files in the base snapshot.

* **Why it's important:** It ensures that the file content on the disk exactly matches your source, detecting corruption that metadata checks might miss.  
* **Can I skip it?** Yes, for daily runs. It is very I/O intensive and slow.  
* **Recommendation:** Run it once a week or once a month.

**Automatic "Road Warrior" Verification:**  
You can configure DEEP\_VERIFY\_INTERVAL\_DAYS="35" (Default: 35\) in your config.  
The script tracks the last successful verification timestamp locally. If more than 35 days have passed since the last verify, the next run will automatically force a verification, even if not explicitly requested. This ensures that laptops which miss their scheduled "1st of month" cron job will still be verified upon their next backup.  
To disable, set DEEP\_VERIFY\_INTERVAL\_DAYS="0".  
**Cron Example (Explicit Monthly Verify)**:  
\# Run a deep verification on the 1st of every month at 02:00  
0 2 1 \* \* root /usr/local/sbin/snapshot-backup.sh \--config /etc/snapshot-backup.conf \--verify

**Scope & Feedback:**

* **Works safely** for both **Local** and **Remote** modes.  
* **Positive Feedback (Exit Code 0):** The run was successful. If corruption was found, rsync **automatically healed** it by re-transferring the correct data from the source. Check the logs: if "Total transferred file size" is 0, your data was perfect. If \> 0, changes (or corruption) were fixed.  
* **Negative Feedback (Exit Code \!= 0):** A "Hard Failure" occurred (e.g. Disk could not be read, Network dropped). This requires manual intervention (Hardware check).

**Troubleshooting Verify Failure (Exit Code \!= 0):**

1. **Check Logs:** Look for I/O errors in dmesg or /var/log/syslog.  
2. **Retry:** Run the command again to rule out transient network issues.

### **6\. Restoration (Mounting & Recovery)**

To restore individual files, you simply "mount" the backup directory.

* **Local Mode**: The directory is already accessible at BACKUP\_ROOT.  
* **Remote Mode**: You can mount the remote storage via SSHFS or simply browse via SFTP/SCP.

#### **Full System Recovery**

If you are restoring a full OS partition (e.g. from a Live USB), remember to verify fstab and recreate excluded system files.  
EXCLUDED FILES Checklist:  
If you used EXCLUDE\_PATTERNS to save space (e.g. swapfile), the system may warn on boot ("Timed out waiting for device"). This is safe but annoying.  
**Fix (Post-Restore):**

1. Boot into the system (Wait for timeout).  
2. Recreate the Swapfile:  
   sudo fallocate \-l 2G /swapfile  
   sudo chmod 600 /swapfile  
   sudo mkswap /swapfile  
   sudo swapon /swapfile

3. Recreate missing empty directories (/proc, /sys) if they were not auto-created by the script's EXCLUDE\_MOUNTPOINTS feature.

\*\* Tip for Laptop Users:\*\*  
If you are on a laptop and checking backups remotely, you can use the status command to verify the last successful run. Since the script uses atomic commits, incomplete backups (e.g. if the laptop went to sleep) are held in a .tmp state and resumed automatically next time.

### **6\. Desktop User Context**

The core backup runs as root in the background. Desktop users do not have permission to modify or mount backups directly.

* **Notifications**: If enabled in config (ENABLE\_NOTIFICATIONS=true), desktop users (logged into GUI) will receive pop-up notifications for defined events (Failures, Success, etc.).

### **7\. Advanced: Debugging & Reference**

#### **Agent Mode (Direct Invocation)**

The script automatically switches to Agent Mode when invoked as snapshot-agent.sh or with \--agent-mode.  
To see available agent commands:  
/usr/local/sbin/snapshot-agent.sh \--help

#### **Wrapper Security Check**

The installed wrapper restricts SSH commands to only allowed operations (rsync, checking status, agent logic).  
To verify the wrapper:  
/usr/local/bin/snapshot-wrapper.sh \--help

## **Full Reference**

### **1\. Command Line Options (snapshot-backup.sh)**

Usage: snapshot-backup.sh \[OPTIONS\]

### **General**

#### **\--config**

* **Function:** Load a specific configuration file instead of the default /etc/snapshot-backup.conf.  
* **Context:** local/remote  
* **Options:** FILE (Path to config)  
* **Example:** snapshot-backup.sh \--config /home/user/myconfig.conf

#### **\--show-config**

* **Function:** Dump the currently loaded configuration and defaults to stdout. Useful for debugging or creating a new config file.  
* **Context:** local  
* **Example:** snapshot-backup.sh \--show-config \> /etc/snapshot-backup.conf

#### **\--status**

* **Function:** Show a summary of existing backup snapshots and storage usage.  
* **Context:** local/remote  
* **Example:** snapshot-backup.sh \--status

#### **\--debug**

* **Function:** Enable verbose debug logging to console and logfile (includes full rsync file lists).  
* **Context:** local/remote  
* **Example:** snapshot-backup.sh \--debug

#### **\--help, \-h**

* **Function:** Show the help message and exit.

#### **\--version**

* **Function:** Show script version.

#### **\--desktop**

* **Function:** Send a desktop notification (via notify-send) with the current status. Useful for verifying notification setup.  
* **Context:** local  
* **Example:** snapshot-backup.sh \--desktop

### **Execution Control**

#### **\--force-weekly, \-f**

* **Function:** Force a weekly promotion run immediately, regardless of the current date.  
* **Context:** local/remote

#### **\--force-monthly, \-m**

* **Function:** Force a monthly promotion run immediately.  
* **Context:** local/remote

#### **\--force-yearly, \-y**

* **Function:** Force a yearly promotion run immediately.  
* **Context:** local/remote

#### **\--verify, \-v**

* **Function:** Force a deep checksum verification relative to the previous snapshot.  
* **Context:** local/remote  
* **Note:** This is an expensive operation (reads all files). Defaults to metadata check (size/mtime) otherwise.

#### **\--kill, \-k**

* **Function:** Kill any currently running backup process for this client (identified by lockfile).  
* **Context:** local  
* **Example:** snapshot-backup.sh \--kill

#### **\--timeout**

* **Function:** Set network timeout in seconds for SSH/Rsync operations.  
* **Default:** 10  
* **Example:** snapshot-backup.sh \--timeout 120

#### **\--service, \-s**

* **Function:** Force Service Mode. Logs are directed to the logfile/syslog instead of stdout, even if run interactively.  
* **Context:** local/remote

### **Helpers & Status Checks**

#### **\--is-running**

* **Function:** Check if a backup is currently running. Returns exit code 0 (True) if running, 1 (False) otherwise.  
* **Context:** local

#### **\--is-job-done**

* **Function:** Check if a valid backup already exists for the current interval (preventing duplicate runs).  
* **Context:** local/remote

#### **\--has-storage**

* **Function:** Check if the backup storage is reachable and writable.  
* **Context:** local/remote

### **Deployment & Agent**

#### **\--setup-remote**

* **Function:** Remote Setup Wizard. Handles SSH Keys, installs the agent script, and applies Security Hardening (Client Locking).  
* **Context:** local (sending to remote)  
* **Options:** \[USER\]@\[HOST\]  
* **Example:** snapshot-backup.sh \--setup-remote root@backup.local

#### **\--deploy-agent (Legacy)**

* **Function:** Alias for \--setup-remote. Kept for backward compatibility.

#### **\--mount**

* **Function:** Mount the backup directory to /tmp/mnt\_backup (or custom path). Uses mount \--bind for local and sshfs for remote.  
* **Context:** local/remote  
* **Options:** \[PATH\] (Optional target mountpoint), \--client \[NAME\] (For remote mode)  
* **Example:** snapshot-backup.sh \--mount /mnt/restore

#### **\--umount**

* **Function:** Unmount the backup directory.  
* **Context:** local/remote  
* **Options:** \[PATH\] (Optional argument to specify what to unmount)

#### **\--agent-mode**

* **Function:** Run in agent mode (server-side logic). Usually invoked automatically via SSH or symlink.  
* **Context:** remote (server-side)

### **2\. Configuration Variables**

#### **2a. Client Configuration (/etc/snapshot-backup.conf)**

### **Storage & Logic**

#### **BACKUP\_ROOT**

* **Function:** Destination path for **LOCAL** mode. Ignored if BACKUP\_MODE="REMOTE".  
* **Default:** /mnt/backup  
* **Example:** BACKUP\_ROOT="/media/usb-drive/backups"

#### **BACKUP\_MODE**

* **Function:** Defines operation mode.  
* **Options:** LOCAL (write to disk), REMOTE (SSH to agent)  
* **Default:** LOCAL

#### **CLIENT\_NAME**

* **Function:** Unique identifier for this client. Used for folder naming on the remote server.  
* **Default:** hostname

### **Remote Connectivity**

#### **REMOTE\_HOST**

* **Function:** IP or Hostname of the backup server.

#### **REMOTE\_USER**

* **Function:** SSH user for the backup server.  
* **Default:** root

#### **REMOTE\_PORT**

* **Function:** SSH port.  
* **Default:** 22

#### **REMOTE\_AGENT**

* **Function:** Absolute path to the snapshot-agent.sh script on the remote server.  
* **Default:** /usr/local/sbin/snapshot-agent.sh

#### **SSH\_KEY**

* **Function:** Private key file for SSH authentication.  
* **Default:** \~/.ssh/id\_ed25519

### **Retention Policy**

#### **RETAIN\_${INTERVAL}**

* **Function:** Number of snapshots to keep for each interval.  
* **Variables:** RETAIN\_HOURLY, RETAIN\_DAILY, RETAIN\_WEEKLY, RETAIN\_MONTHLY, RETAIN\_YEARLY  
* **Default:** Daily: 7, Weekly: 4, Monthly: 12, Yearly: 5

#### **DEEP\_VERIFY\_INTERVAL\_DAYS**

* **Function:** Interval in days to force a deep checksum verification. Supports "Road Warriors" by catching up on verification if machine was offline.  
* **Default:** 35 (Set to 0 to disable)

#### **SPACE\_LOW\_LIMIT\_GB**

* **Function:** Low disk space threshold (in GB). If free space is below this limit, retention is reduced.  
* **Default:** 0 (Disabled)

#### **SMART\_PURGE\_SLOTS**

* **Function:** Number of slots to reduce from retention rules when low space is detected.  
* **Default:** 0

### **Sources & Filters**

#### **SOURCE\_DIRS**

* **Function:** Multi-line string of local directory paths to back up.  
* **Example:**  
  SOURCE\_DIRS='  
      "/etc"  
      "/home"  
  '

#### **EXCLUDE\_PATTERNS**

* **Function:** Multi-line string of rsync exclude patterns.  
* **Example:** EXCLUDE\_PATTERNS=' "\*.tmp" ".cache/" '

#### **EXCLUDE\_MOUNTPOINTS**

* **Function:** Multi-line string of mountpoints to exclude.  
* **Example:** EXCLUDE\_MOUNTPOINTS=' "/proc" "/sys" '

### **System Config**

#### **LOGFILE**

* **Function:** Path to the log file.  
* **Default:** /var/log/snapshot-backup.log

#### **PIDFILE**

* **Function:** Path to the lock file. Prevents multiple backup instances from running simultaneously (which could corrupt data or thrash IO). The \--kill command uses this file to identify the process ID of the running job.  
* **Default:** /var/run/snapshot-backup.pid

#### **ENABLE\_NOTIFICATIONS**

* **Function:** Send desktop notifications via notify-send for start/finish/error events.  
* **Options:** true / false  
* **Default:** false

#### **LOG\_PROGRESS\_INTERVAL**

* **Function:** Seconds between progress updates for long-running rsync operations.  
* **Default:** 60

#### **RSYNC\_EXTRA\_OPTS**

* **Function:** Additional flags to pass directly to the rsync command.  
* **Example:** RSYNC\_EXTRA\_OPTS="--bwlimit=1000"

#### **2b. Agent Configuration (/etc/snapshot-agent.conf)**

#### **BASE\_STORAGE**

* **Function:** **Overwrites the storage root.** Where the agent stores incoming backups on the server.  
* **Default:** /var/backups/snapshots (if not set)

#### **LOCK\_DIR**

* **Function:** Directory for lock files.  
* **Default:** /var/run/snapshot-agent

## **Developer & Architecture Notes**

### **Unified Single-File Design**

The project uses a single file snapshot-backup.sh to simplify distribution and versioning.

* **Client Logic**: Runs when executed as snapshot-backup.sh. Handles configuration, locking, and orchestration of rsync.  
* **Agent Logic**: Runs when executed as snapshot-agent.sh (symlink) or with \--agent-mode. Handles local filesystem operations on the server side (prepare, commit, purge).

### **Remote Protocol (Command Pattern)**

The Client does not run arbitrary commands on the server. Instead, it triggers specific **Actions** via SSH:

1. **Prepare**: Agent creates \<backup\_root\>/daily.0.tmp.  
2. **Transfer**: Client rsyncs data directly into daily.0.tmp.  
3. **Commit**: Agent rotates old snapshots and renames .tmp to daily.0.

### **Root Requirement & Security Trade-Off**

This tool is designed for **System Backups**, which inherently requires root privileges on both ends:

* **Client**: To read all files (/etc/shadow, /home/\*) and preserve their ownership/permission attributes.  
* **Server**: To write those files and chown them to their original users (UIDs/GIDs).

**Security Implication**: Since the backup process requires a root SSH connection (albeit wrapped), a compromised client technically possesses elevated privileges on the backup server (via rsync).  
**Mitigation Strategies**:

1. **Trusted Networks (Primary Defense)**: Use this tool only in LANs or VPNs where you trust the clients. It is **not** designed for Zero-Trust environments.  
2. **Security Wrapper (Logical Defense)**: Use the wrapper to lock SSH keys to specific client names. This prevents accidental overwrites or "spoofing" of other clients.  
3. **Dedicated User (Defense in Depth)**: Advanced users can configure a dedicated backup user on the server (manual setup required).  
   * Create user: useradd \-m backup  
   * Configure sudo to allow backup to run specific execution logic as root.  
   * *Limitation*: Even with a dedicated user, sudo access for rsync is effectively root file access. This adds a layer of defense (no direct root login), but does NOT sandbox the file system access.

### **Testing**

Use integration-test.sh for all changes. It creates a self-contained environment (no root needed for local tests) and verifies:

* Retention logic (waterfall).  
* Error handling (locking, timeout).  
* Remote simulation.

## **Version History**

* **v17.00**: Major Release.  
  * Unified Core Logic (Local/Remote parity).  
  * Robust Seeding of missing intervals (automatic gap filling).  
  * Recursive Calendar/Waterfall promotion for better consistency.  
  * Strict integer sanitization & Shell hardening.  
* **v16.0**: Strict POSIX compliance refactoring. Configuration schema v2.0. Improved variable scoping.  
* **v15.1**: Security & Usability Update. Added \--setup-remote wizard with strict client-name checks and auto-hardening (SSH authorized\_keys lock).  
* **v15.0**: POSIX sh Rewrite. BusyBox capability (fallback for timeout/ACLs). Debug mode.  
* **v14.1**: Integration Suite improvements.  
* **v14.0**: Unified Client & Agent. Added self-deployment and help functionality.  
* **v13.xx**: Legacy split-script architecture.

## **License**

GPLv3