#ifndef __included_my_start_node_h__
#define __included_my_start_node_h__

// ─────────────────────────────────────────────────────────────────────────────
// my_start_node.h
//
// This header file declares shared data that other .c files in the plugin
// can use. Think of it as a "table of contents" for the plugin.
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>
#include <vnet/vnet.h>

// This struct holds all the global state for our plugin.
// "Global state" = data that lives for the entire lifetime of VPP.
typedef struct
{
    // File descriptor for the TAP interface
    // -1 means "not opened yet"
    int tap_fd;

    // Name of the TAP interface we will open (e.g. "mytap0")
    char tap_name[64];

    // How many packets have we received total (just for fun / debugging)
    u64 total_rx_packets;

} my_start_main_t;

// Declare the global instance - defined in my_plugin.c
// "extern" means: "this variable exists somewhere else, not here"
extern my_start_main_t my_start_main;

// Declare the node registration so other files can reference it
extern vlib_node_registration_t my_start_node;

#endif // __included_my_start_node_h__
