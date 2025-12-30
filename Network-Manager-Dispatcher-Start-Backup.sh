#!/bin/bash

# ==============================================================================
# @file      Network-Manager-Dispatcher-Start-Backup.sh
# @brief     NetworkManager dispatcher for hybrid backup automation.
# @details   Triggers snapshot-backup.sh based on network events, power state,
#            trusted networks, and specific safety pre-checks.
#
# @version   5.0 (Added: Extended Safety Checks & Systemd Optimization)
# @license   GPLv3
# ==============================================================================

# ==============================================================================
# 1. CONFIGURATION & CONSTANTS
# ==============================================================================

# NetworkManager arguments
INTERFACE="$1"
ACTION="$2"

# Configuration Files
DISPATCHER_CONF="/etc/snapshot-backup-dispatcher.conf"
BACKUP_CONF="/etc/snapshot-backup.conf"

# Binaries
BACKUP_SCRIPT="/usr/local/sbin/snapshot-backup.sh"
LOGGER_BIN="/usr/bin/logger"
SYSTEMD_RUN="/usr/bin/systemd-run"
SYSTEMD_INHIBIT="/usr/bin/systemd-inhibit"
NOTIFY_SEND="/usr/bin/notify-send"

# Logging Tag
LOG_TAG="nm-backup-dispatcher"

# Defaults
declare -a HOME_NETWORKS=()

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
    for ps in /sys/class/power_supply/*; do
        if [ -r "$ps/type" ] && grep -q "Mains" "$ps/type"; then
            if [ -r "$ps/online" ] && grep -q "1" "$ps/online"; then return 0; fi
        fi
    done
    # Method B: on_ac_power utility
    if command -v on_ac_power >/dev/null; then
        if on_ac_power; then return 0; fi
    fi
    # Fallback: Assume AC if no battery detected
    if [ ! -d "/sys/class/power_supply" ]; then return 0; fi
    
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
# @brief Main logic wrapper to be detached.
run_logic() {
    # Delay for network stabilization (DHCP lease, routing table update)
    sleep 10

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
        local current_con="${CONNECTION_ID:-}"
        if [ -z "$current_con" ]; then
            current_con=$(nmcli -t -f NAME connection show --active | head -n 1)
        fi

        local match=false
        for net in "${HOME_NETWORKS[@]}"; do
            if [[ "$current_con" == "$net" ]]; then match=true; break; fi
        done

        if [ "$match" = false ]; then
            log "SKIP: Network '$current_con' is not trusted."
            exit 0
        else
            log "TRUST: Network '$current_con' is trusted."
        fi
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
    if ! "$BACKUP_SCRIPT" --has-storage --timeout 1 >/dev/null 2>&1; then
        log "SKIP: Safety Check 'has-storage' failed (Target unreachable/unwritable)."
        exit 0
    fi
    log "TEST: Storage is verified and available."

    # Check B: Prevent concurrent backup executions
    if "$BACKUP_SCRIPT" --is-running --timeout 1 >/dev/null 2>&1; then
        log "SKIP: Safety Check 'is-running' failed (Instance already active)."
        exit 0
    fi
    log "TEST: No existing backup process detected."

    # Check C: Verify if the job is already completed for the current interval
    #if "$BACKUP_SCRIPT" --is-job-done --timeout 1 >/dev/null 2>&1; then
    #    log "SKIP: Safety Check 'is-job-done' failed (Interval already covered)."
    #    exit 0
    #fi
    #log "TEST: Backup interval is open; job is required."

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

# Only trigger on 'up' or 'vpn-up' events
if [[ "$ACTION" != "up" && "$ACTION" != "vpn-up" ]]; then exit 0; fi

# Filter out virtual/docker/loopback interfaces
if [[ "$INTERFACE" =~ ^(docker|br-|lo|veth|vnet) ]]; then exit 0; fi

# Detach logic to avoid blocking NetworkManager's dispatcher process
run_logic &

exit 0

