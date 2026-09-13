#!/bin/sh
# TheKVM unattended updater for Linux Mint (installed by tools/mint-ssh-update.ps1).
# Polls the GitHub HEAD; rebuilds + restarts only when it moved. Logs to
# /var/log/thekvm-auto-update.log. Runs as root from thekvm-update.timer.
set -eu
REPO="https://github.com/xyzyt010/thekvm.git"
BRANCH="main"
DESKTOP_USER="hs01"
CHECKOUT="/home/$DESKTOP_USER/thekvm"
STAMP="/var/lib/thekvm-built-commit"
LOG="/var/log/thekvm-auto-update.log"
export PATH="/home/$DESKTOP_USER/.cargo/bin:/usr/bin:/bin"
REMOTE="$(git ls-remote "$REPO" "$BRANCH" | awk '{print $1}')"
BUILT="$(cat "$STAMP" 2>/dev/null || echo none)"
if [ "$REMOTE" = "$BUILT" ]; then exit 0; fi
{
  echo "$(date -u): $BUILT -> $REMOTE"
  git -C "$CHECKOUT" fetch --prune origin
  git -C "$CHECKOUT" checkout "$BRANCH"
  git -C "$CHECKOUT" pull --ff-only origin "$BRANCH"
  sudo -u "$DESKTOP_USER" env PATH="$PATH" sh -c "cd \"$CHECKOUT\" && cargo build --release -p kvm-daemon -p kvm-ui"
  sh "$CHECKOUT/packaging/linux/install.sh" --desktop-user "$DESKTOP_USER" --no-dependencies
  systemctl restart thekvmd
  echo "$REMOTE" > "$STAMP"
  echo "$(date -u): updated ok"
} >>"$LOG" 2>&1
