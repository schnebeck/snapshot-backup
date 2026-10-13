#!/bin/bash
# file: test-dispatcher.sh
# Tests for Network-Manager-Dispatcher-Start-Backup.sh. No root, no NetworkManager:
# every outside command is a stub, and a "backup" is a stub systemd-run writing a marker.
#
#   bash test-dispatcher.sh [path/to/dispatcher.sh]

DISPATCHER="$(readlink -f "${1:-Network-Manager-Dispatcher-Start-Backup.sh}")"
T=$(mktemp -d)
trap 'kill $LISTENER 2>/dev/null; rm -rf "$T"' EXIT
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
RUN=0; FAILED=0

# A TCP port to stand in for the backup server's sshd.
python3 -c '
import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1",0)); s.listen(16); print(s.getsockname()[1], flush=True)
while True:
    c,_=s.accept(); c.close()
' > "$T/port" &
LISTENER=$!
while [ ! -s "$T/port" ]; do sleep 0.1; done
PORT=$(cat "$T/port")

mkdir -p "$T/bin" "$T/ps/AC" "$T/ps/BAT0"
echo Mains > "$T/ps/AC/type"; echo Battery > "$T/ps/BAT0/type"
printf '#!/bin/sh\necho "$*" >> "%s/log"\n' "$T" > "$T/bin/logger"
printf '#!/bin/sh\necho "$*" >> "%s/triggered"\n' "$T" > "$T/bin/systemd-run"
printf '#!/bin/sh\nexit 1\n' > "$T/bin/on_ac_power"
# nmcli: the active connections, one per line, in the order of $T/active
printf '#!/bin/sh\ncat "%s/active"\n' "$T" > "$T/bin/nmcli"
# snapshot-backup.sh: --has-storage succeeds, --is-running fails, --is-job-done reads $T/done
cat > "$T/bin/backup" <<EOF
#!/bin/sh
case "\$1" in
  --has-storage) exit 0 ;;
  --is-running)  exit 1 ;;
  --is-job-done) [ -f "$T/done" ] && exit 0 || exit 1 ;;
esac
exit 0
EOF
chmod +x "$T/bin/"*
cat > "$T/backup.conf" <<EOF
BACKUP_MODE="REMOTE"
REMOTE_HOST="127.0.0.1"
REMOTE_PORT="$PORT"
EOF

# setup <ac 0|1> <active connections, comma separated> <done 0|1> [dispatcher config lines...]
setup() {
    rm -f "$T/triggered" "$T/log" "$T/done"
    echo "$1" > "$T/ps/AC/online"
    printf '%s\n' "$2" | tr ',' '\n' > "$T/active"
    [ "$3" = 1 ] && touch "$T/done"
    shift 3
    { echo 'HOME_NETWORKS=("MeyersGarten" "schnebeck.de VPN")'
      echo "BACKUP_SCRIPT=\"$T/bin/backup\""
      printf '%s\n' "$@"; } > "$T/dispatcher.conf"
}

# dispatch <interface> <action> [CONNECTION_ID]; waits for a detached run to finish
dispatch() {
    local conn=(); [ -n "${3:-}" ] && conn=("CONNECTION_ID=$3")
    env -i PATH="$T/bin:/usr/bin:/bin" "${conn[@]}" \
        DISPATCHER_CONF="$T/dispatcher.conf" BACKUP_CONF="$T/backup.conf" \
        POWER_SUPPLY_DIR="$T/ps" NM_SETTLE_SECONDS=0 CHECK_TIMEOUT=2 \
        LOGGER_BIN="$T/bin/logger" SYSTEMD_RUN="$T/bin/systemd-run" \
        NMCLI="$T/bin/nmcli" ON_AC_POWER_BIN="$T/bin/on_ac_power" \
        bash "$DISPATCHER" "$1" "$2" >/dev/null 2>&1
    # an event run is detached; give it time (the old script sleeps 10 s first)
    local i=0; while [ $i -lt 130 ]; do
        grep -qE "^(SKIP|TRIGGER|ERROR)" "$T/log" 2>/dev/null && break
        sleep 0.1; i=$((i+1))
    done
}

expect() {  # expect <triggered|skipped> <name>
    RUN=$((RUN+1))
    local got=skipped; [ -s "$T/triggered" ] && got=triggered
    if [ "$got" = "$1" ]; then printf "%-66s ${GREEN}PASS${NC}\n" "$2"
    else FAILED=$((FAILED+1)); printf "%-66s ${RED}FAIL${NC} (%s, log: %s)\n" "$2" "$got" "$(tail -1 "$T/log" 2>/dev/null)"; fi
}

# --- the gaps this release closes -------------------------------------------
setup 1 "schnebeck.de VPN,MeyersGarten" 0
dispatch - timer
expect triggered "timer: AC plugged in later, at home -> backs up"

setup 1 "Hotel-WiFi,docker0" 0
dispatch - timer
expect skipped "timer: untrusted network only -> no backup"

setup 1 "MeyersGarten" 1
dispatch - timer
expect skipped "timer: already backed up this period -> no second run"

setup 0 "MeyersGarten" 0
dispatch - timer
expect skipped "timer: on battery -> no backup"

setup 1 "Hotel-WiFi,schnebeck.de VPN" 0
dispatch - timer
expect triggered "timer: away, VPN up and trusted -> backs up over the VPN"

# --- event behaviour that must not change -----------------------------------
setup 1 "MeyersGarten" 0
dispatch wlp3s0 up MeyersGarten
expect triggered "event: trusted Wi-Fi comes up on AC -> backs up"

setup 1 "Hotel-WiFi" 0
dispatch wlp3s0 up Hotel-WiFi
expect skipped "event: untrusted Wi-Fi comes up -> no backup"

setup 1 "Hotel-WiFi,schnebeck.de VPN" 0
dispatch tun0 vpn-up "schnebeck.de VPN"
expect triggered "event: trusted VPN comes up -> backs up"

setup 1 "MeyersGarten" 1
dispatch wlp3s0 up MeyersGarten
expect triggered "event: done this period, default -> runs again (in place)"

setup 1 "MeyersGarten" 1 "RUN_ONCE_PER_PERIOD=true"
dispatch wlp3s0 up MeyersGarten
expect skipped "event: done this period, RUN_ONCE_PER_PERIOD=true -> skips"

setup 1 "MeyersGarten" 0
dispatch docker0 up MeyersGarten
expect skipped "event: virtual interface -> ignored"

setup 1 "MeyersGarten" 0
dispatch wlp3s0 down MeyersGarten
expect skipped "event: interface down -> ignored"

echo "------------------------------------------------"
echo "Tests Run: $RUN | Failures: $FAILED"
[ "$FAILED" -eq 0 ]
