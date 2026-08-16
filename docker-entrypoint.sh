#!/bin/sh
# Runs network namespace setup, then starts the merged API+worker.
#
# Setup runs from THIS container's network namespace so the host end of each
# veth pair and the host-side NAT/forwarding rules live in a namespace that
# persists for the life of the container. A separate init container would let
# its own namespace (and the veth host end) die as soon as it exited.
set -e

if [ "${SKIP_NETNS_SETUP:-0}" != "1" ]; then
    nmapaas-netns setup
fi

exec "$@"
