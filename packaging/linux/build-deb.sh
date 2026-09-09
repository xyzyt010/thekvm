#!/bin/sh
# Build thekvm .deb on the target Linux machine. Run from ~/thekvm-build.
# Layout: ./in holds the release binaries; metadata is generated here.
set -eu
cd ~/thekvm-build
VER=0.5.0
PKG=thekvm
ROOT=debroot
rm -rf "$ROOT" "${PKG}_${VER}_amd64.deb"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/bin" \
         "$ROOT/lib/systemd/system" \
         "$ROOT/usr/lib/systemd/user" \
         "$ROOT/etc/udev/rules.d" \
         "$ROOT/etc/modules-load.d" \
          "$ROOT/usr/share/applications" \
          "$ROOT/etc/xdg/autostart" \
          "$ROOT/usr/share/doc/$PKG"

install -m 0755 in/kvm-daemon "$ROOT/usr/bin/kvm-daemon"
install -m 0755 in/kvm-ui "$ROOT/usr/bin/kvm-ui"

cat > "$ROOT/lib/systemd/system/thekvmd.service" <<'EOF'
[Unit]
Description=TheKVM cross-OS KVM receiver daemon
After=network-online.target systemd-udev-settle.service
Wants=network-online.target
ConditionPathExists=/dev/uinput

[Service]
Type=simple
User=thekvm
Group=thekvm
SupplementaryGroups=input
ExecStart=/usr/bin/kvm-daemon serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/thekvm
PrivateTmp=yes
ProtectHome=yes
DeviceAllow=/dev/uinput rw
UMask=0007

[Install]
WantedBy=multi-user.target
EOF

cat > "$ROOT/lib/systemd/system/thekvm-agent.service" <<'EOF'
[Unit]
Description=TheKVM physical input controller agent
After=network-online.target thekvmd.service
Wants=network-online.target

[Service]
Type=simple
User=thekvm
Group=thekvm
SupplementaryGroups=input
Environment=THEKVM_DATA_DIR=/var/lib/thekvm
ExecStart=/usr/bin/kvm-daemon connect
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/thekvm
PrivateTmp=yes
ProtectHome=yes
DeviceAllow=/dev/input/event* r
UMask=0007

[Install]
WantedBy=multi-user.target
EOF

cat > "$ROOT/usr/lib/systemd/user/thekvm-agent-user.service" <<'EOF'
[Unit]
Description=TheKVM logged-in desktop controller agent
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
Environment=THEKVM_DATA_DIR=%h/.local/share/thekvm
ExecStart=/usr/bin/kvm-daemon connect
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=graphical-session.target
EOF

cat > "$ROOT/etc/udev/rules.d/99-thekvm-uinput.rules" <<'EOF'
KERNEL=="uinput", GROUP="input", MODE="0660"
EOF

printf 'uinput\n' > "$ROOT/etc/modules-load.d/thekvm.conf"

cat > "$ROOT/usr/share/applications/thekvm-ui.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=TheKVM
GenericName=Cross-OS keyboard/mouse sharing
Comment=Pair and control nearby machines with one keyboard and mouse
Exec=/usr/bin/kvm-ui
Icon=preferences-desktop-peripherals
Terminal=false
Categories=Network;Utility;
Keywords=kvm;keyboard;mouse;synergy;deskflow;
EOF

# Start the UI at graphical login so approvals can never be missed because
# the app was never opened. The UI single-instance lock makes a manual
# launch alongside this harmless.
cp "$ROOT/usr/share/applications/thekvm-ui.desktop" "$ROOT/etc/xdg/autostart/thekvm-ui.desktop"

cat > "$ROOT/usr/share/doc/$PKG/copyright" <<'EOF'
TheKVM is licensed under GPL-3.0-or-later.
Upstream: https://github.com/xyzyt010/thekvm
EOF

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Depends: libfontconfig1 (>= 2.13)
Maintainer: TheKVM project
Homepage: https://github.com/xyzyt010/thekvm
Description: Cross-OS software KVM over QUIC
 Keyboard and mouse sharing between Windows and Linux machines
 over an authenticated QUIC transport, with optional lock-screen
 control and a six-digit pairing ceremony.
EOF

cat > "$ROOT/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = "install" ] || [ "$1" = "upgrade" ]; then
    modprobe uinput || true
fi
EOF

cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
  configure)
    # Service account: system user/group with uinput access.
    if ! getent group thekvm >/dev/null; then
        groupadd --system thekvm
    fi
    if ! id thekvm >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /var/lib/thekvm \
            --shell /usr/sbin/nologin --gid thekvm thekvm
    fi
    usermod --append --groups input thekvm 2>/dev/null || true

    # Enroll the invoking (sudo) desktop user so the UI can reach control.sock.
    DESKTOP_USER=${SUDO_USER:-}
    if [ -z "$DESKTOP_USER" ] && [ -f /root/.thekvm-install-user ]; then
        DESKTOP_USER=$(cat /root/.thekvm-install-user)
    fi
    if [ -n "$DESKTOP_USER" ] && id "$DESKTOP_USER" >/dev/null 2>&1; then
        usermod --append --groups thekvm "$DESKTOP_USER"
        # The Connect button supervises a user-session controller that reads
        # the physical devices directly; applies on next login.
        usermod --append --groups input "$DESKTOP_USER" 2>/dev/null || true
    fi

    install -d -o thekvm -g thekvm -m 0770 /var/lib/thekvm

    # Station-side edge control runs as the desktop user (thekvm group) and
    # reads the system identity and peer book to dial with the trusted
    # identity. Additive only: the group gains read, nothing is removed.
    for f in identity.key peers.json config.json; do
        [ -e "/var/lib/thekvm/$f" ] && chmod g+r "/var/lib/thekvm/$f" || true
    done

    udevadm control --reload-rules || true
    udevadm trigger --name-match=uinput || true

    if [ ! -e /dev/uinput ]; then
        echo "TheKVM: /dev/uinput is not available; lock-screen input will not work until the kernel module loads." >&2
    fi

    systemctl daemon-reload
    systemctl enable --now thekvmd.service
    echo "TheKVM receiver service installed and running."
    echo "Log out and back in so the 'thekvm' group applies to your desktop session, then launch TheKVM from the start menu."
    ;;
esac
EOF

cat > "$ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop thekvmd.service 2>/dev/null || true
    systemctl disable thekvmd.service 2>/dev/null || true
fi
EOF

cat > "$ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = "purge" ]; then
    systemctl daemon-reload 2>/dev/null || true
    rm -rf /var/lib/thekvm
fi
EOF

chmod 0755 "$ROOT/DEBIAN/preinst" "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm" "$ROOT/DEBIAN/postrm"

# dpkg-deb needs root-owned files for correct ownership; fakeroot is not
# guaranteed, and we run this under sudo on the target anyway.
sudo chown -R root:root "$ROOT"
sudo dpkg-deb --build --root-owner-group "$ROOT" "${PKG}_${VER}_amd64.deb"
echo "BUILT: ~/thekvm-build/${PKG}_${VER}_amd64.deb"
