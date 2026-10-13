#!/bin/bash

# ==============================================================================
# @file      Network-Manager-Dispatcher-Start-Backup.sh
# @brief     NetworkManager dispatcher for hybrid backup automation.
# @details   Triggers snapshot-backup.sh based on network events, power state,
#            trusted networks, and specific safety pre-checks.
#
# @version   5.1 (Added: timer trigger, trust over all active connections,
#                  RUN_ONCE_PER_PERIOD)
# @license   GPLv3
# ==============================================================================

# ==============================================================================
# 1. CONFIGURATION & CONSTANTS
# ==============================================================================

# NetworkManager arguments: interface and event ("up", "vpn-up", ...).
# The systemd timer calls this script as "<script> - timer"; see section 3.
INTERFACE="$1"
ACTION="$2"

# Paths. Overridable from the environment only so that test-dispatcher.sh can
# run the script without root; NetworkManager and systemd pass none of these.
DISPATCHER_CONF="${DISPATCHER_CONF:-/etc/snapshot-backup-dispatcher.conf}"
BACKUP_CONF="${BACKUP_CONF:-/etc/snapshot-backup.conf}"
POWER_SUPPLY_DIR="${POWER_SUPPLY_DIR:-/sys/class/power_supply}"

# Binaries
BACKUP_SCRIPT="/usr/local/sbin/snapshot-backup.sh"
LOGGER_BIN="${LOGGER_BIN:-/usr/bin/logger}"
SYSTEMD_RUN="${SYSTEMD_RUN:-/usr/bin/systemd-run}"
SYSTEMD_INHIBIT="/usr/bin/systemd-inhibit"
NOTIFY_SEND="${NOTIFY_SEND:-/usr/bin/notify-send}"
NMCLI="${NMCLI:-nmcli}"
ON_AC_POWER_BIN="${ON_AC_POWER_BIN:-on_ac_power}"

# Logging Tag
LOG_TAG="nm-backup-dispatcher"

# Seconds to wait after a network event before checking anything (DHCP lease,
# routing table). The timer skips the wait: its network has long settled.
NM_SETTLE_SECONDS="${NM_SETTLE_SECONDS:-10}"

# Timeout for the checks that ask the backup server (--has-storage,
# --is-job-done). One second was enough at home; over the VPN from a hotel an
# SSH handshake takes longer, and an --is-job-done that times out reads as
# "not done" - which, from an hourly timer, would mean a backup every hour.
CHECK_TIMEOUT="${CHECK_TIMEOUT:-10}"

# Defaults, overridable in DISPATCHER_CONF
declare -a HOME_NETWORKS=()
# false: every trusted network event backs up, into the current period's
#        snapshot if one exists (in-place update) - the behaviour before 5.1.
# true:  a network event backs up only if this period has no backup yet.
# The timer always behaves as "true".
RUN_ONCE_PER_PERIOD=false

# ==============================================================================
# 2. HELPER FUNCTIONS
# ==============================================================================

##
# @brief Log a message to syslog.
log() {
    "$LOGGER_BIN" -t "$LOG_TAG" "$1"
}

##
# @brief Checks if the system is running on AC power (Mains).
# @return 0 if on AC power, 1 if on Battery.
check_power() {
    # Method A: sysfs check
    for ps in "$POWER_SUPPLY_DIR"/*; do
        if [ -r "$ps/type" ] && grep -q "Mains" "$ps/type"; then
            if [ -r "$ps/online" ] && grep -q "1" "$ps/online"; then return 0; fi
        fi
    done
    # Method B: on_ac_power utility
    if command -v "$ON_AC_POWER_BIN" >/dev/null; then
        if "$ON_AC_POWER_BIN"; then return 0; fi
    fi
    # Fallback: Assume AC if no battery detected
    if [ ! -d "$POWER_SUPPLY_DIR" ]; then return 0; fi
    
    return 1
}

##
# @brief Sends a notification to active GUI users.
notify_user() {
    local title="$1"
    local body="$2"
    local urgency="${3:-normal}"
    
    if ! command -v "$NOTIFY_SEND" >/dev/null; then return; fi

    # Iterate over all active user sessions
    for user_dir in /run/user/*; do
        if [ -d "$user_dir" ]; then
            local uid
            uid=$(basename "$user_dir")
            # Filter system users (standard users start at 1000)
            if [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -ge 1000 ]; then
                local bus_address="unix:path=$user_dir/bus"
                if [ -S "$user_dir/bus" ]; then
                    # Send notification as the specific user session
                    sudo -u "#$uid" \
                        DBUS_SESSION_BUS_ADDRESS="$bus_address" \
                        XDG_RUNTIME_DIR="$user_dir" \
                        "$NOTIFY_SEND" -u "$urgency" -i "drive-harddisk" \
                        -a "Backup System" "$title" "$body" 2>/dev/null || true
                fi
            fi
        fi
    done
}

##
# @brief True if a trusted network is in use; sets TRUSTED_NET to its name.
#
# A network event names the connection that came up (CONNECTION_ID), and only
# that one is judged. Without one - the timer - every active connection counts.
# Before 5.1 the first line of "nmcli connection show --active" stood in for
# all of them, and with the VPN up that line is the VPN: at home, on the trusted
# Wi-Fi, the check then judged the tunnel and skipped.
is_trusted_network() {
    local -a candidates=()
    if [ -n "${CONNECTION_ID:-}" ]; then
        candidates=("$CONNECTION_ID")
    else
        mapfile -t candidates < <("$NMCLI" -t -f NAME connection show --active 2>/dev/null)
    fi
    local c net
    for c in "${candidates[@]}"; do
        for net in "${HOME_NETWORKS[@]}"; do
            if [[ "$c" == "$net" ]]; then TRUSTED_NET="$c"; return 0; fi
        done
    done
    TRUSTED_NET="${candidates[*]}"
    return 1
}

##
# @brief Main logic: runs detached after a network event, in the foreground
#        from the timer.
run_logic() {
    # Delay for network stabilization (DHCP lease, routing table update)
    [ "$MODE" = event ] && sleep "$NM_SETTLE_SECONDS"

    # 1. Power State Check
    if ! check_power; then
        log "SKIP: System is on battery power."
        exit 0
    fi

    # 2. Load Dispatcher Config for Trusted Networks
    if [ -f "$DISPATCHER_CONF" ]; then
        # shellcheck source=/dev/null
        source "$DISPATCHER_CONF"
    else
        log "WARN: Dispatcher config missing. Allowing all networks."
    fi

    # 3. Network Trust Validation
    if [ ${#HOME_NETWORKS[@]} -gt 0 ]; then
        if ! is_trusted_network; then
            log "SKIP: Network '$TRUSTED_NET' is not trusted."
            exit 0
        fi
        log "TRUST: Network '$TRUSTED_NET' is trusted."
    fi

    # 4. Load Core Backup Configuration
    if [ -f "$BACKUP_CONF" ]; then
        # shellcheck source=/dev/null
        source "$BACKUP_CONF"
    else
        log "ERROR: Backup configuration file missing."
        exit 1
    fi

    # 5. Basic Connectivity Checks
    local connectivity_ok=false
    if [ "$BACKUP_MODE" == "REMOTE" ]; then
        log "CHECK: Connectivity to Remote Host ($REMOTE_HOST)..."
        local port
        port=$(echo "$REMOTE_PORT" | awk '{print $1}')
        if timeout 5 bash -c "</dev/tcp/$REMOTE_HOST/$port" 2>/dev/null; then
             connectivity_ok=true
        fi
    elif [ "$BACKUP_MODE" == "LOCAL" ]; then
        log "CHECK: Connectivity for Local Mode..."
        if mountpoint -q "$BACKUP_ROOT" || ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
             connectivity_ok=true
        fi
    fi

    if [ "$connectivity_ok" = false ]; then
        log "SKIP: Basic connectivity check failed."
        exit 0
    fi

    # 6. Advanced Safety Invariants (Script-based checks)
    
    # Check A: Verify storage availability and writability
    if ! "$BACKUP_SCRIPT" --has-storage --timeout "$CHECK_TIMEOUT" >/dev/null 2>&1; then
        log "SKIP: Safety Check 'has-storage' failed (Target unreachable/unwritable)."
        exit 0
    fi
    log "TEST: Storage is verified and available."

    # Check B: Prevent concurrent backup executions
    if "$BACKUP_SCRIPT" --is-running --timeout "$CHECK_TIMEOUT" >/dev/null 2>&1; then
        log "SKIP: Safety Check 'is-running' failed (Instance already active)."
        exit 0
    fi
    log "TEST: No existing backup process detected."

    # Check C: Verify if the job is already completed for the current interval.
    # Always for the timer, which would otherwise back up every hour; for network
    # events only with RUN_ONCE_PER_PERIOD=true (see section 1).
    if [ "$MODE" = timer ] || [ "$RUN_ONCE_PER_PERIOD" = true ]; then
        if "$BACKUP_SCRIPT" --is-job-done --timeout "$CHECK_TIMEOUT" >/dev/null 2>&1; then
            log "SKIP: Safety Check 'is-job-done' failed (Interval already covered)."
            exit 0
        fi
        log "TEST: Backup interval is open; job is required."
    fi

    # 7. Final Execution via Systemd
    if [ -x "$BACKUP_SCRIPT" ]; then
        log "TRIGGER: Initiating backup via systemd-run..."
        notify_user "Backup Started" "Mode: $BACKUP_MODE" "normal"
        
        # NOTE: Using --collect ensures the transient unit is unloaded immediately after completion,
        # preventing "Unit already loaded" errors on subsequent dispatcher events.
        $SYSTEMD_RUN --unit="snapshot-backup-auto" \
                     --description="Automated Snapshot Backup" \
                     --collect \
                     --quiet \
                     $SYSTEMD_INHIBIT --what=sleep --why="Backup in progress" --mode=delay \
                     "$BACKUP_SCRIPT"
    else
        log "ERROR: Script not executable or not found: $BACKUP_SCRIPT"
    fi
}

# ==============================================================================
# 3. MAIN ENTRY POINT
# ==============================================================================

# "timer": called by snapshot-backup-check.timer (see README). A network event
# fires once per connection, so on its own it misses a laptop that is plugged
# in after arriving on battery, and one that stays on the same network for days.
# The timer runs the same checks in the foreground; Check C keeps it to one
# backup per period.
if [ "$ACTION" = "timer" ]; then
    MODE=timer
    run_logic
    exit 0
fi
MODE=event

# Only trigger on 'up' or 'vpn-up' events
if [[ "$ACTION" != "up" && "$ACTION" != "vpn-up" ]]; then exit 0; fi

# Filter out virtual/docker/loopback interfaces
if [[ "$INTERFACE" =~ ^(docker|br-|lo|veth|vnet) ]]; then exit 0; fi

# Detach logic to avoid blocking NetworkManager's dispatcher process
run_logic &

exit 0

