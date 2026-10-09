#!/bin/sh
set -eu

/usr/lib/ipsec/charon &
charon_pid=$!

cleanup() {
    kill "$charon_pid" 2>/dev/null || true
    wait "$charon_pid" 2>/dev/null || true
}
trap cleanup INT TERM

attempt=0
until swanctl --load-all; do
    if ! kill -0 "$charon_pid" 2>/dev/null; then
        wait "$charon_pid"
        exit $?
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "strongSwan VICI became ready, but swanctl could not load configuration" >&2
        exit 1
    fi
    sleep 1
done

if [ "${VISTA_INITIATE:-0}" = "1" ]; then
    child="${VISTA_CHILD:-pc-tunnel}"
    echo "Initiating IPsec child SA: $child..."
    init_attempt=0
    until swanctl --initiate --child "$child" 2>/dev/null; do
        init_attempt=$((init_attempt + 1))
        if [ "$init_attempt" -ge 20 ]; then
            echo "Warning: swanctl could not initiate child $child within 20s" >&2
            break
        fi
        sleep 1
    done
fi

wait "$charon_pid"
