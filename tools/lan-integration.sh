#!/bin/sh
set -eu

# Run two disposable daemons locally to validate the authenticated control
# plane without requiring /dev/uinput or a graphical session. This is the
# Unix counterpart to lan-integration.ps1 and is intended for Linux/FreeBSD
# CI and operator smoke tests.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BINARY=${1:-"$PROJECT_DIR/target/release/kvm-daemon"}
if [ ! -x "$BINARY" ]; then
    echo "kvm-daemon binary is not executable: $BINARY" >&2
    exit 1
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/thekvm-lan-integration.XXXXXX")
data_a="$root/node-a"
data_b="$root/node-b"
mkdir -p "$data_a" "$data_b"
pid_a=
pid_b=
pair_pid_a=
pair_pid_b=

cleanup()
{
    if [ -n "${pid_a:-}" ] && kill -0 "$pid_a" 2>/dev/null; then
        kill "$pid_a" 2>/dev/null || true
        wait "$pid_a" 2>/dev/null || true
    fi
    if [ -n "$pid_b" ] && kill -0 "$pid_b" 2>/dev/null; then
        kill "$pid_b" 2>/dev/null || true
        wait "$pid_b" 2>/dev/null || true
    fi
    if [ -n "$pair_pid_a" ] && kill -0 "$pair_pid_a" 2>/dev/null; then
        kill "$pair_pid_a" 2>/dev/null || true
        wait "$pair_pid_a" 2>/dev/null || true
    fi
    if [ -n "$pair_pid_b" ] && kill -0 "$pair_pid_b" 2>/dev/null; then
        kill "$pair_pid_b" 2>/dev/null || true
        wait "$pair_pid_b" 2>/dev/null || true
    fi
    rm -rf -- "$root"
}
trap cleanup EXIT INT TERM

run_a()
{
    THEKVM_DATA_DIR="$data_a" "$BINARY" "$@"
}

run_b()
{
    THEKVM_DATA_DIR="$data_b" "$BINARY" "$@"
}

run_a_confirmed()
{
    THEKVM_DATA_DIR="$data_a" THEKVM_AUTO_CONFIRM=1 "$BINARY" "$@"
}

run_b_confirmed()
{
    THEKVM_DATA_DIR="$data_b" THEKVM_AUTO_CONFIRM=1 "$BINARY" "$@"
}

wait_for_pending()
{
    data_dir=$1
    label=$2
    attempt=0
    while [ "$attempt" -lt 60 ]; do
        pending=$(THEKVM_DATA_DIR="$data_dir" "$BINARY" pending-pairings 2>/dev/null || true)
        fingerprint=$(python3 -c '
import json
import sys

items = json.loads(sys.argv[1])
if not items:
    print("")
    raise SystemExit(0)
code = items[0].get("verification_code", "")
if len(code) != 6 or not code.isdigit():
    raise SystemExit(
        "pending pairing on "
        + sys.argv[2]
        + " carries no valid six-digit verification code: "
        + repr(code)
    )
print(items[0]["fingerprint_hex"])
' "$pending" "$label") || exit 1
        if [ -n "$fingerprint" ]; then
            printf '%s\n' "$fingerprint"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    echo "timed out waiting for pending pairing on $label" >&2
    return 1
}

run_a configure --listen-port 42120 --device-name "Integration A" \
    --mode server-client --allow-lock-screen-control
run_b configure --listen-port 42122 --device-name "Integration B" \
    --mode receiver-only --allow-lock-screen-control

THEKVM_DATA_DIR="$data_a" "$BINARY" serve >"$root/node-a.log" 2>&1 &
pid_a=$!
THEKVM_DATA_DIR="$data_b" "$BINARY" serve >"$root/node-b.log" 2>&1 &
pid_b=$!
sleep 1

run_a_confirmed pair 127.0.0.1:42122 >"$root/pair-a.log" 2>&1 &
pair_pid_a=$!
fingerprint_b=$(wait_for_pending "$data_b" "node-b")
run_b approve-pairing "$fingerprint_b"
wait "$pair_pid_a"
pair_pid_a=

run_b_confirmed pair 127.0.0.1:42120 >"$root/pair-b.log" 2>&1 &
pair_pid_b=$!
fingerprint_a=$(wait_for_pending "$data_a" "node-a")
run_a approve-pairing "$fingerprint_a"
wait "$pair_pid_b"
pair_pid_b=

status_a=$(run_a status)
status_b=$(run_b status)
python3 -c '
import json
import sys

a, b = map(json.loads, sys.argv[1:])
if a["node_name"] != "Integration A" or b["node_name"] != "Integration B":
    raise SystemExit("configured device names did not survive daemon startup")
if a["peer_count"] != 1 or b["peer_count"] != 1:
    raise SystemExit("reciprocal pairing did not produce one trusted peer on each daemon")
if a["mode"] != "ServerClient" or b["mode"] != "ClientOnly":
    raise SystemExit("strict one-way roles were not preserved by daemon startup")
' "$status_a" "$status_b"

set +e
receiver_failure=$(run_b send 127.0.0.1:42120 2>&1)
receiver_code=$?
set -e
if [ "$receiver_code" -eq 0 ]; then
    echo "receiver-only mode unexpectedly initiated an input session" >&2
    exit 1
fi
case "$receiver_failure" in
    *"receiver-only mode cannot initiate an input session"*) ;;
    *)
        echo "unexpected receiver-only rejection: $receiver_failure" >&2
        exit 1
        ;;
esac

fingerprint_a=$(run_a fingerprint | tail -n 1)
run_b unpair "$(printf '%s' "$fingerprint_a" | tr '[:lower:]' '[:upper:]')"
status_b=$(run_b status)
python3 -c '
import json
import sys
if json.loads(sys.argv[1])["peer_count"] != 0:
    raise SystemExit("uppercase fingerprint revocation was not applied immediately")
' "$status_b"

echo "LAN integration passed: two-sided approval, QUIC pairing, strict controller/receiver roles, configured names, status, and live revocation."
