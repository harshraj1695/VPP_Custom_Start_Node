#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh
#
# Run this script IN LINUX before starting VPP.
# It creates the TAP interface that our plugin will read from.
#
# Usage:
#   chmod +x setup.sh
#   sudo ./setup.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e  # stop script if any command fails

TAP_NAME="mytap0"
TAP_IP="10.0.0.1"
TAP_PREFIX="24"

echo "=== Setting up TAP interface: $TAP_NAME ==="

# Step 1: Remove existing interface if it already exists (so we start fresh)
if ip link show "$TAP_NAME" &>/dev/null; then
    echo "  Removing existing $TAP_NAME..."
    ip link delete "$TAP_NAME"
fi

# Step 2: Create the TAP interface
# mode tap = Ethernet frames (vs mode tun = IP packets)
echo "  Creating $TAP_NAME..."
ip tuntap add dev "$TAP_NAME" mode tap

# Step 3: Bring the interface UP
echo "  Bringing $TAP_NAME up..."
ip link set "$TAP_NAME" up

# Step 4: Assign an IP address to it
# This lets Linux know this interface is in the 10.0.0.0/24 network
echo "  Assigning IP $TAP_IP/$TAP_PREFIX to $TAP_NAME..."
ip addr add "$TAP_IP/$TAP_PREFIX" dev "$TAP_NAME"

# Step 5: Show the result
echo ""
echo "=== TAP interface ready ==="
ip addr show "$TAP_NAME"

echo ""
echo "=== Now start VPP. The plugin will open $TAP_NAME automatically. ==="
echo ""
echo "To send a test packet into VPP via the TAP interface:"
echo "  ping 10.0.0.2"
echo ""
echo "To watch what VPP is doing:"
echo "  vppctl show errors"
echo "  vppctl show node my-start-node"
echo "  vppctl trace add my-start-node 10"
echo "  vppctl show trace"
