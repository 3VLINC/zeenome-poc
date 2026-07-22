#!/usr/bin/env bash
# Ensure enough swap for SP1 core proving (peaks ~14–28 GiB RSS/VM).
#
# Cloud/dev containers often mount overlayfs, which rejects plain `swapon` on a
# file (EINVAL). We allocate a swapfile with dd and activate it via a loop
# device, which works on overlay.
#
# Safe to re-run; no-ops when enough swap is already active.
set -euo pipefail

# Target total swap (existing + new). Override with POC_SWAP_SIZE_GB.
TARGET_GIB="${POC_SWAP_SIZE_GB:-32}"
SWAPFILE="${POC_SWAPFILE:-/var/tmp/zeenome-poc.swap}"
LOOP_LINK="${POC_SWAP_LOOP_LINK:-/var/tmp/zeenome-poc.swap.loop}"

have_sudo() {
  command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

current_swap_kib() {
  awk '/^SwapTotal:/ { print $2 }' /proc/meminfo
}

current_gib="$(awk -v kib="$(current_swap_kib)" 'BEGIN { printf "%.0f", kib / 1024 / 1024 }')"
if (( current_gib >= TARGET_GIB )); then
  echo "swap: ${current_gib} GiB already active (need ≥ ${TARGET_GIB} GiB)"
  exit 0
fi

if ! have_sudo; then
  echo "swap: need ~${TARGET_GIB} GiB for SP1 prove; only ${current_gib} GiB active." >&2
  echo "swap: re-run with passwordless sudo, or on the host:" >&2
  echo "  sudo dd if=/dev/zero of=${SWAPFILE} bs=1M count=$((TARGET_GIB * 1024))" >&2
  echo "  sudo chmod 600 ${SWAPFILE}" >&2
  echo "  LOOP=\$(sudo losetup --find --show ${SWAPFILE})" >&2
  echo "  sudo mkswap \"\$LOOP\" && sudo swapon \"\$LOOP\"" >&2
  exit 0
fi

# Reuse an existing loop mapping if we left one behind.
if [[ -e "$LOOP_LINK" ]]; then
  existing_loop="$(readlink -f "$LOOP_LINK" 2>/dev/null || true)"
  if [[ -n "$existing_loop" && -b "$existing_loop" ]]; then
    if ! grep -qF "$existing_loop" /proc/swaps; then
      echo "swap: re-activating ${existing_loop}"
      sudo mkswap "$existing_loop" >/dev/null
      sudo swapon "$existing_loop" || true
    fi
  fi
fi

current_gib="$(awk -v kib="$(current_swap_kib)" 'BEGIN { printf "%.0f", kib / 1024 / 1024 }')"
if (( current_gib >= TARGET_GIB )); then
  echo "swap: ${current_gib} GiB already active"
  swapon --show || true
  exit 0
fi

# Need a fresh (or resized) file. Always use dd — fallocate sparse files and
# overlayfs both cause swapon EINVAL in this environment.
echo "swap: creating ${TARGET_GIB} GiB at ${SWAPFILE} (SP1 prove is memory-heavy)"
sudo rm -f "$SWAPFILE"
sudo dd if=/dev/zero of="$SWAPFILE" bs=1M count=$((TARGET_GIB * 1024)) status=progress
sudo chmod 600 "$SWAPFILE"

# Detach any prior loop on this file.
if command -v losetup >/dev/null 2>&1; then
  while read -r old; do
    [[ -n "$old" ]] && sudo losetup -d "$old" || true
  done < <(sudo losetup -j "$SWAPFILE" -O NAME -n 2>/dev/null || true)
fi

LOOP="$(sudo losetup --find --show "$SWAPFILE")"
echo "swap: loop device ${LOOP}"
sudo ln -sfn "$LOOP" "$LOOP_LINK"
sudo mkswap "$LOOP" >/dev/null
sudo swapon "$LOOP"

after_gib="$(awk -v kib="$(current_swap_kib)" 'BEGIN { printf "%.0f", kib / 1024 / 1024 }')"
echo "swap: ${after_gib} GiB active now"
swapon --show || true

if (( after_gib < TARGET_GIB )); then
  echo "swap: warning — only ${after_gib} GiB active (wanted ${TARGET_GIB})." >&2
  echo "swap: cgroup memory.swap.max may cap usable swap; check /sys/fs/cgroup/memory.swap.max" >&2
fi
