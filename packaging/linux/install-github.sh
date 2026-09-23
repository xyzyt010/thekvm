#!/bin/sh
# TheKVM one-shot installer for Linux Mint (Ubuntu family).
# Fetches this repo, builds release binaries, installs the receiver service.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xyzyt010/thekvm/main/packaging/linux/install-github.sh | sudo bash
# or, to enroll a desktop user explicitly:
#   curl -fsSL .../install-github.sh -o /tmp/thekvm-install.sh && sudo bash /tmp/thekvm-install.sh --desktop-user "$USER"
set -eu

REPO_URL="https://github.com/xyzyt010/thekvm.git"
BRANCH="main"
WORK_DIR="/tmp/thekvm-build-src"
DESKTOP_USER="${SUDO_USER:-${USER:-}}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --desktop-user)
            DESKTOP_USER="$2"
            shift 2
            ;;
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "usage: $0 [--desktop-user LOGIN] [--branch NAME]" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (try: curl ... | sudo bash)" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config \
    libdbus-1-dev libfontconfig1-dev libinput-dev libwayland-dev \
    libx11-xcb-dev libxi-dev libxkbcommon-dev libxtst-dev \
    libayatana-appindicator3-dev || apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config \
    libdbus-1-dev libfontconfig1-dev libinput-dev libwayland-dev \
    libx11-xcb-dev libxi-dev libxkbcommon-dev libxtst-dev

# Rust toolchain (system-wide install when missing).
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable
    export PATH="$PATH:/root/.cargo/bin"
fi
export PATH="$PATH:/root/.cargo/bin:$HOME/.cargo/bin"

rm -rf "$WORK_DIR"
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$WORK_DIR"
cd "$WORK_DIR"
cargo build --release --workspace

if [ -n "$DESKTOP_USER" ]; then
    THEKVM_DESKTOP_USER="$DESKTOP_USER" sh packaging/linux/install.sh --desktop-user "$DESKTOP_USER"
else
    sh packaging/linux/install.sh
fi

echo ""
echo "TheKVM installed from $REPO_URL ($BRANCH)."
echo "Launch TheKVM from the start menu, pair with your Windows machine,"
echo "then Connect. Log out and back in once so group membership applies."
