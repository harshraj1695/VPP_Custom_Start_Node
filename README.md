# VPP Custom TAP Start Node Plugin

A complete beginner-friendly VPP plugin that creates a fully independent
packet pipeline reading from a Linux TAP interface.

## Pipeline

```
Linux TAP (mytap0)
       │
       │  read() syscall
       ▼
my-start-node       ← INPUT node: reads raw Ethernet frames from TAP
       │
       ▼
your-parser-node    ← strips Ethernet header, routes IPv4 to firewall
       │
       ▼
your-firewall-node  ← blocks packets from 192.168.1.100, allows rest
       │
       ▼
your-output-node    ← writes allowed packets back to TAP / Linux
```

## Project Structure

```
vpp_tap_plugin/
├── README.md                  ← you are here
├── setup.sh                   ← creates the Linux TAP interface
├── startup.conf               ← VPP startup configuration
└── my_plugin/
    ├── CMakeLists.txt         ← build configuration
    ├── my_plugin.api          ← VPP API messages for runtime control
    ├── my_plugin.c            ← plugin init, global state
    ├── my_start_node.h        ← shared header (global state struct)
    ├── tap_utils.h            ← TAP open/close function declarations
    ├── tap_utils.c            ← TAP open/close implementation
    ├── my_start_node.c        ← INPUT node: reads from TAP
    ├── your_parser_node.c     ← INTERNAL node: parses Ethernet
    ├── your_firewall_node.c   ← INTERNAL node: IP-based blocking
    └── your_output_node.c     ← INTERNAL node: sends to TAP output
```

## Step-by-Step Setup

### Step 1 — Install VPP (if not already installed)

```bash
# Ubuntu/Debian
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
sudo apt-get install vpp vpp-dev vpp-plugin-core
```

### Step 2 — Copy plugin into VPP source tree

```bash
# Clone VPP source (if you don't have it)
git clone https://github.com/FDio/vpp.git
cd vpp

# Copy our plugin folder into VPP's plugin directory
cp -r /path/to/vpp_tap_plugin/my_plugin src/plugins/
```

### Step 3 — Build the plugin

```bash
# From the VPP source root:
make build

# Or for a faster debug build:
make build-release
```

### Step 4 — Create the TAP interface in Linux

```bash
# Run BEFORE starting VPP
sudo ./setup.sh

# What it does:
#   ip tuntap add dev mytap0 mode tap
#   ip link set mytap0 up
#   ip addr add 10.0.0.1/24 dev mytap0
```

### Step 5 — Start VPP

```bash
sudo vpp -c startup.conf
```

### Step 6 — Verify the pipeline is working

```bash
# Open vppctl in another terminal
sudo vppctl

# Check our nodes are registered
vppctl show node my-start-node
vppctl show node your-parser-node
vppctl show node your-firewall-node
vppctl show node your-output-node

# Enable packet tracing (capture next 10 packets)
vppctl trace add my-start-node 10

# Send a test packet from Linux
ping 10.0.0.2   # in another terminal

# View the trace
vppctl show trace

# View error counters
vppctl show errors
```

## Understanding the Code

### Node Types

| Type | Meaning | Example |
|------|---------|---------|
| `VLIB_NODE_TYPE_INPUT` | VPP polls this node itself (no upstream) | `my-start-node` |
| `VLIB_NODE_TYPE_INTERNAL` | Receives packets from another node | all other nodes |

### Key VPP Concepts

**Buffer index (bi):** VPP doesn't pass raw pointers between nodes.
Instead it passes 32-bit indices. Use `vlib_get_buffer(vm, bi)` to get a pointer.

**Frame:** A batch of up to 256 buffer indices that flow between nodes together.
Processing in batches is what makes VPP fast.

**vlib_get_next_frame / vlib_put_next_frame:** The way you "enqueue" packets
to the next node. Always call these as a pair.

**O_NONBLOCK on TAP fd:** Without this, `read()` would block (wait forever)
when no packet is available. With it, `read()` returns -1 immediately if
there is no packet, so VPP's main loop can keep running.

### Firewall Rule

The firewall blocks all IPv4 packets from `192.168.1.100`.
To change this, edit these lines in `your_firewall_node.c`:

```c
#define BLOCKED_IP_BYTE0 192
#define BLOCKED_IP_BYTE1 168
#define BLOCKED_IP_BYTE2   1
#define BLOCKED_IP_BYTE3 100
```

## Runtime Commands

```bash
# Disable start node (stop reading from TAP)
vppctl set node state my-start-node disable

# Re-enable it
vppctl set node state my-start-node polling

# Watch live counters
watch -n1 'vppctl show errors | grep -E "my-start|parser|firewall|output"'
```

## Troubleshooting

**TAP not opening:**
Make sure you ran `setup.sh` BEFORE starting VPP.
Check `ip link show mytap0` to confirm the interface exists.

**No packets arriving:**
Verify the TAP interface is UP: `ip link show mytap0`
Try pinging from Linux: `ping 10.0.0.2`
Enable tracing: `vppctl trace add my-start-node 100`

**Build errors:**
Make sure `vpp-dev` is installed and you copied the plugin to `src/plugins/`.
Run `make build` from the VPP root, not from inside the plugin folder.
