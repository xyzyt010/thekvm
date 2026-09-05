#!/bin/sh
# Approve the currently pending pairing on the local TheKVM daemon.
for i in $(seq 1 15); do
    p=$(THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon pending-pairings 2>/dev/null || true)
    fp=$(printf '%s' "$p" | grep -oE '[0-9a-f]{64}' | head -1)
    if [ -n "$fp" ]; then
        echo "PENDING_FP=$fp"
        code=$(printf '%s' "$p" | grep -oE '"verification_code": "[0-9]{6}"' | grep -oE '[0-9]{6}' | head -1)
        echo "REMOTE_CODE=$code"
        THEKVM_DATA_DIR=/var/lib/thekvm kvm-daemon approve-pairing "$fp"
        exit 0
    fi
    sleep 1
done
echo "NO_PENDING_PAIRING"
exit 1
