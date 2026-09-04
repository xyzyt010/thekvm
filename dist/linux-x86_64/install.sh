#!/bin/sh
set -eu

# Install the release binaries and the privileged receiver service. Run this
# script as root from a source checkout after `cargo build --release`.

DESKTOP_USER=${THEKVM_DESKTOP_USER:-${SUDO_USER:-}}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --desktop-user)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "--desktop-user requires an existing login name" >&2
                exit 2
            fi
            DESKTOP_USER=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "usage: $0 [--desktop-user LOGIN]" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
RELEASE_DIR=${RELEASE_DIR:-"$PROJECT_DIR/target/release"}
PREFIX=/usr
DATA_DIR=/var/lib/thekvm
SERVICE_USER=thekvm
SERVICE_GROUP=thekvm

if [ ! -x "$RELEASE_DIR/kvm-daemon" ]; then
    echo "missing $RELEASE_DIR/kvm-daemon; run cargo build --release first" >&2
    exit 1
fi

# The receiver's virtual HID devices are created at the kernel input layer,
# including before a graphical login. Load uinput now and persist the module
# load for subsequent boots; silently installing without this device would
# produce a service that appears active but cannot control a greeter.
if command -v modprobe >/dev/null 2>&1; then
    if ! modprobe uinput; then
        echo "cannot load the Linux uinput module; pre-login input is unavailable" >&2
        exit 1
    fi
else
    echo "modprobe is required to load Linux uinput" >&2
    exit 1
fi

install -d -m 0755 "$PREFIX/bin"
install -m 0755 "$RELEASE_DIR/kvm-daemon" "$PREFIX/bin/kvm-daemon"
if [ -x "$RELEASE_DIR/kvm-ui" ]; then
    install -m 0755 "$RELEASE_DIR/kvm-ui" "$PREFIX/bin/kvm-ui"
fi

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin --gid "$SERVICE_GROUP" "$SERVICE_USER"
fi
if getent group input >/dev/null 2>&1; then
    usermod --append --groups input "$SERVICE_USER"
else
    echo "warning: input group does not exist; /dev/input and /dev/uinput access must be configured manually" >&2
fi
if [ -n "$DESKTOP_USER" ]; then
    if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
        echo "desktop user '$DESKTOP_USER' does not exist" >&2
        exit 1
    fi
    usermod --append --groups "$SERVICE_GROUP" "$DESKTOP_USER"
else
    echo "warning: no desktop user selected; pass --desktop-user LOGIN or set THEKVM_DESKTOP_USER so the UI can access control.sock" >&2
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0770 "$DATA_DIR"

# A fresh system installation is a receiver by default. Preserve an existing
# operator-managed configuration on reinstall; an explicit configure command
# can still select bidirectional or controller-only operation later.
if [ ! -e "$DATA_DIR/config.json" ]; then
    THEKVM_DATA_DIR="$DATA_DIR" "$PREFIX/bin/kvm-daemon" configure --mode receiver-only
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/config.json"
fi

install -D -m 0644 "$SCRIPT_DIR/99-thekvm-uinput.rules" \
    /etc/udev/rules.d/99-thekvm-uinput.rules
install -D -m 0644 "$SCRIPT_DIR/thekvm.conf" \
    /etc/modules-load.d/thekvm.conf
install -D -m 0644 "$SCRIPT_DIR/thekvmd.service" \
    /etc/systemd/system/thekvmd.service
install -D -m 0644 "$SCRIPT_DIR/thekvm-agent.service" \
    /etc/systemd/system/thekvm-agent.service

if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
    udevadm trigger --subsystem-match=input || true
    udevadm trigger --name-match=uinput || true
fi
if [ ! -e /dev/uinput ]; then
    echo "Linux uinput did not create /dev/uinput; refusing incomplete receiver installation" >&2
    exit 1
fi
systemctl daemon-reload
systemctl enable --now thekvmd.service

cat <<EOF
TheKVM receiver installed.
  binary:  $PREFIX/bin/kvm-daemon
  state:   $DATA_DIR
  service: thekvmd.service (enabled and running)

The desktop user must be in the '$SERVICE_GROUP' group to use the UI/control
socket. Start a new login session after adding that user to the group.

The optional physical-input controller remains disabled. Pair peers and
configure a layout first, then enable it explicitly with:
  systemctl enable --now thekvm-agent.service
EOF
