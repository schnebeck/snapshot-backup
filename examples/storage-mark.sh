#!/bin/sh
# ==============================================================================
## @file    storage-mark.sh
## @brief   Mounts a backup disk on demand: one mark per caller, mounted while
##          any mark is left, unmounted after the last one is gone.
##
## @details Example hook for snapshot-backup.sh, client (STORAGE_*) and agent
##          (AGENT_*) alike. A backup run and a status request each hold their
##          own mark, so the end of one never pulls the disk from under the
##          other. Plain POSIX sh; runs on busybox.
##
##          storage-mark.sh up     MARK MOUNTPOINT   set MARK, mount if needed
##          storage-mark.sh down   MARK MOUNTPOINT   remove MARK, unmount if none is left
##          storage-mark.sh status MOUNTPOINT        list the marks and the mount state
##
##          MOUNTPOINT needs an /etc/fstab entry with "noauto", e.g.
##            UUID=...  /mnt/usb-backup  ext4  noauto,nofail  0  2
##
##          Environment (all optional):
##            STORAGE_MARK_DIR     where marks live (default /run/storage-mark;
##                                 a tmpfs, so a reboot clears them with the mount)
##            STORAGE_MARK_MOUNT   mount command, given MOUNTPOINT (default: mount)
##            STORAGE_MARK_UMOUNT  unmount command, given MOUNTPOINT (default: umount)
##            STORAGE_MARK_WAIT    seconds to wait for another caller's lock (default 60)
##
## @producedby thorsten.schnebeck@gmx.net
## @generator  Claude Opus 5.5
## @license GPLv3
##
## SPDX-FileCopyrightText: (C) 2026 Thorsten Schnebeck <thorsten.schnebeck@gmx.net>
## SPDX-License-Identifier: GPL-3.0-only
# ==============================================================================

set -u
export LC_ALL=C

MARK_ROOT="${STORAGE_MARK_DIR:-/run/storage-mark}"
MOUNT_CMD="${STORAGE_MARK_MOUNT:-mount}"
UMOUNT_CMD="${STORAGE_MARK_UMOUNT:-umount}"
WAIT_MAX="${STORAGE_MARK_WAIT:-60}"

say() { echo "storage-mark: $*" >&2; command -v logger >/dev/null 2>&1 && logger -t storage-mark -- "$*"; return 0; }
fail() { say "$*"; exit 1; }
usage() { fail "usage: storage-mark.sh up|down MARK MOUNTPOINT | status MOUNTPOINT"; }

## @brief Returns 0 when $1 is a mount point (mountpoint, else /proc/mounts).
is_mounted() {
    if command -v mountpoint >/dev/null 2>&1; then
        mountpoint -q "$1"
        return
    fi
    awk -v m="$1" '$2 == m { found = 1 } END { exit !found }' /proc/mounts
}

## @brief Takes the lock of this mount point: a directory holding the PID.
## A holder that no longer runs is stale and removed, so is a lock without a
## PID after 5 s (its holder died between mkdir and writing it); after
## WAIT_MAX seconds of a live holder it gives up.
lock() {
    local waited=0 holder
    mkdir -p "$MARKS" || fail "cannot create $MARKS"
    while ! mkdir "$LOCK" 2>/dev/null; do
        holder=$(cat "$LOCK/pid" 2>/dev/null)
        if { [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; } || { [ -z "$holder" ] && [ "$waited" -ge 5 ]; }; then
            say "removing stale lock $LOCK (PID ${holder:-none})"
            rm -rf "$LOCK"
        fi
        [ "$waited" -ge "$WAIT_MAX" ] && fail "lock $LOCK held by PID ${holder:-?} for ${WAIT_MAX}s - giving up"
        sleep 1
        waited=$((waited + 1))
    done
    echo $$ > "$LOCK/pid"
    trap 'rm -rf "$LOCK"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

## @brief Prints the marks left for this mount point, one per line. Marks never
## start with a dot, so "*" sees all of them and never the lock.
list_marks() {
    local f
    for f in "$MARKS"/*; do
        [ -e "$f" ] && echo "${f##*/}"
    done
    return 0
}

case "${1:-}" in
    up|down) [ $# -eq 3 ] || usage; ACTION="$1"; MARK="$2"; MNT="${3%/}" ;;
    status)  [ $# -eq 2 ] || usage; ACTION="status"; MARK=""; MNT="${2%/}" ;;
    *) usage ;;
esac
[ -n "$MNT" ] || MNT="/"
case "$MNT" in /*) ;; *) fail "MOUNTPOINT must be an absolute path: $MNT" ;; esac
case "$MARK" in */*|.*) fail "invalid mark: $MARK" ;; esac
case "$WAIT_MAX" in ''|*[!0-9]*) fail "STORAGE_MARK_WAIT must be a whole number: $WAIT_MAX" ;; esac

# One directory of marks per mount point: /mnt/usb-backup -> _mnt_usb-backup
MARKS="$MARK_ROOT/$(echo "$MNT" | tr '/' '_')"
LOCK="$MARKS/.lock"

case "$ACTION" in
    status)
        if is_mounted "$MNT"; then echo "$MNT: mounted"; else echo "$MNT: not mounted"; fi
        list_marks | sed 's/^/  mark: /'
        exit 0
        ;;
    up)
        lock
        : > "$MARKS/$MARK" || fail "cannot write mark $MARKS/$MARK"
        if ! is_mounted "$MNT"; then
            $MOUNT_CMD "$MNT" >&2 || fail "mounting $MNT failed (mark $MARK kept; 'down' removes it)"
            say "mounted $MNT for $MARK"
        fi
        # The caller relies on the disk, not on the mount command's word.
        is_mounted "$MNT" || fail "$MNT is not mounted after '$MOUNT_CMD $MNT'"
        ;;
    down)
        lock
        rm -f "$MARKS/$MARK"
        [ -n "$(list_marks)" ] && exit 0
        if is_mounted "$MNT"; then
            sync
            # Busy (a shell still in it): the disk stays mounted, the safe side.
            $UMOUNT_CMD "$MNT" >&2 || fail "unmounting $MNT failed - it stays mounted"
            say "unmounted $MNT after $MARK"
        fi
        ;;
esac
exit 0
