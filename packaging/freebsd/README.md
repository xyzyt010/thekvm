# FreeBSD initial backend

TheKVM can now compile its evdev/uinput backend for FreeBSD. This deployment
template targets FreeBSD systems with the `evdev` and `uinput` drivers enabled;
it is not a claim that every BSD derivative exposes the same device ABI.

The backend expects `/dev/input/event*` for physical capture and `/dev/uinput`
for virtual keyboard/mouse injection. Validate the nodes before enabling the
service:

```sh
kldload evdev
kldload uinput
ls -l /dev/input/event* /dev/uinput
```

Create the service account and apply the devfs rules:

```sh
pw groupadd thekvm
pw useradd thekvm -g thekvm -d /var/db/thekvm -m -s /usr/sbin/nologin
install -d -o thekvm -g thekvm -m 0770 /var/db/thekvm
install -m 0644 packaging/freebsd/devfs.rules /etc/devfs.rules
sysrc devfs_system_ruleset=thekvm
service devfs restart
```

Install `packaging/freebsd/thekvm` as `/etc/rc.d/thekvm`, place
`kvm-daemon` at `/usr/local/bin/kvm-daemon`, then enable the receiver:

```sh
sysrc thekvm_enable=YES
service thekvm start
```

The default rc command is `serve`, and a fresh data directory is initialized
in strict `receiver-only` mode. A controller-only host can set
`thekvm_command=connect` in `/etc/rc.conf` after configuring and pairing a
topology; use `kvm-daemon configure --mode server-client` for the corresponding
role. Physical input capture is privileged on this initial backend, so enable
it only on an explicitly trusted controller/receiver.

The packaged Unix UI uses `/var/db/thekvm/control.sock` on FreeBSD. Add the
desktop user to the `thekvm` group so it can use the socket without `sudo`.

FreeBSD's evdev/uinput availability and desktop/seat behavior must still be
tested on the exact release and display stack before publishing it as a
supported lock-screen target.
