#!/bin/sh
# TheKVM one-shot installer for Linux Mint (Ubuntu family).
# Fast path (default): download the Actions-built .deb from the latest
# GitHub release and install it — no toolchain, no compiling.
# Fallback: --from-source clones this repo and builds release binaries.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xyzyt010/thekvm/main/packaging/linux/install-github.sh | sudo bash
# Explicit desktop user / pinned version / source build:
#   curl -fsSL .../install-github.sh -o /tmp/thekvm-install.sh
#   sudo bash /tmp/thekvm-install.sh --desktop-user "$USER"
#   sudo bash /tmp/thekvm-install.sh --version 0.9.50
#   sudo bash /tmp/thekvm-install.sh --from-source
set -eu

REPO="xyzyt010/thekvm"
VERSION="latest"
FROM_SOURCE=0
DESKTOP_USER="${SUDO_USER:-${USER:-}}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --desktop-user)
            DESKTOP_USER="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --from-source)
            FROM_SOURCE=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "usage: $0 [--desktop-user LOGIN] [--version VER|latest] [--from-source]" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (try: curl ... | sudo bash)" >&2
    exit 1
fi

install_from_source() {
    REPO_URL="https://github.com/$REPO.git"
    WORK_DIR="/tmp/thekvm-build-src"
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
    if ! command -v cargo >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
        sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable
        export PATH="$PATH:/root/.cargo/bin"
    fi
    export PATH="$PATH:/root/.cargo/bin:$HOME/.cargo/bin"
    rm -rf "$WORK_DIR"
    git clone --depth 1 --branch main "$REPO_URL" "$WORK_DIR"
    cd "$WORK_DIR"
    cargo build --release -p kvm-daemon -p kvm-ui
    if [ -n "$DESKTOP_USER" ]; then
        # install.sh reads THEKVM_DESKTOP_USER/SUDO_USER to enroll the user.
        if [ -z "${SUDO_USER:-}" ]; then
            export SUDO_USER="$DESKTOP_USER"
        fi
        THEKVM_DESKTOP_USER="$DESKTOP_USER" sh packaging/linux/install.sh --desktop-user "$DESKTOP_USER"
    else
        sh packaging/linux/install.sh
    fi
}

install_from_release() {
    if [ "$VERSION" = "latest" ]; then
        API_URL="https://api.github.com/repos/$REPO/releases/latest"
    else
        TAG="v$VERSION"
        case "$VERSION" in
            v*) TAG="$VERSION" ;;
        esac
        API_URL="https://api.github.com/repos/$REPO/releases/tags/$TAG"
    fi
    echo "fetching release metadata from $API_URL ..."
    DEB_URL=$(curl -fsSL "$API_URL" | grep browser_download_url | grep amd64.deb | head -n 1 | cut -d'"' -f4)
    if [ -z "$DEB_URL" ]; then
        echo "no amd64 .deb found in release $VERSION" >&2
        exit 1
    fi
    echo "downloading $DEB_URL ..."
    curl -fsSL -o /tmp/thekvm.deb "$DEB_URL"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # The .deb postinst creates the service account, enrolls $SUDO_USER,
    # loads uinput, and enables the receiver service.
    apt-get install -y /tmp/thekvm.deb
    rm -f /tmp/thekvm.deb
}

if [ "$FROM_SOURCE" = "1" ]; then
    install_from_source
else
    install_from_release
fi

echo ""
echo "TheKVM installed."
echo "Log out and back in once so group membership applies, then launch"
echo "TheKVM from the start menu, pair with your Windows machine, Connect."
