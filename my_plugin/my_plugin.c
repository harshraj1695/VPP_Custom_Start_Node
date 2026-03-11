// ─────────────────────────────────────────────────────────────────────────────
// my_plugin.c
//
// Plugin entry point.
//
// This file does two things:
//   1. Defines the global plugin state (my_start_main)
//   2. Runs initialization code at VPP startup (open TAP, start node polling)
//
// VPP automatically calls my_plugin_init() during startup because of the
// VLIB_INIT_FUNCTION macro at the bottom.
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>   // VLIB_PLUGIN_REGISTER macro

#include "my_start_node.h"        // my_start_main_t definition
#include "tap_utils.h"            // tap_open_interface()

// ── Global plugin state ───────────────────────────────────────────────────────
// This is the single global instance of our state struct.
// All files that include my_start_node.h and declare "extern my_start_main_t"
// will share this same object.
my_start_main_t my_start_main;

// ── Plugin initialization ─────────────────────────────────────────────────────
// VPP calls this function once at startup.
// We use it to:
//   - Set default values
//   - Open the TAP interface
//   - Enable our start node
static clib_error_t *
my_plugin_init (vlib_main_t *vm)
{
    my_start_main_t *msm = &my_start_main;
    clib_error_t *error  = 0;

    // Step 1: Initialize default values
    msm->tap_fd           = -1;       // -1 = not open yet
    msm->total_rx_packets = 0;
    strncpy (msm->tap_name, "mytap0", sizeof (msm->tap_name) - 1);

    clib_warning ("my_plugin: initializing...");

    // Step 2: Open the TAP interface
    // Make sure you created it in Linux BEFORE starting VPP:
    //   sudo ip tuntap add dev mytap0 mode tap
    //   sudo ip link set mytap0 up
    //   sudo ip addr add 10.0.0.1/24 dev mytap0
    msm->tap_fd = tap_open_interface (msm->tap_name);
    if (msm->tap_fd < 0)
    {
        // Not fatal - we just won't receive any packets
        // You can open it later via a vppctl command (see my_plugin.api)
        clib_warning ("my_plugin: WARNING - could not open TAP '%s'."
                      " Create it in Linux first.", msm->tap_name);
    }

    // Step 3: Enable our start node so VPP starts polling it
    // vlib_get_node_by_name() finds the node registered with that name
    // vlib_node_set_state() sets it to POLLING (called every main loop tick)
    vlib_node_t *start_node =
        vlib_get_node_by_name (vm, (u8 *) "my-start-node");

    if (start_node == 0)
    {
        // This should never happen if my_start_node.c compiled correctly
        return clib_error_return (0, "my_plugin: 'my-start-node' not found!");
    }

    vlib_node_set_state (vm, start_node->index, VLIB_NODE_STATE_POLLING);
    clib_warning ("my_plugin: 'my-start-node' set to POLLING");

    clib_warning ("my_plugin: init complete. Pipeline ready:");
    clib_warning ("  my-start-node → your-parser-node"
                  " → your-firewall-node → your-output-node");

    return error;  // 0 = no error
}

// This macro tells VPP to call my_plugin_init() at startup.
// The _vlib_init_function suffix is added automatically.
VLIB_INIT_FUNCTION (my_plugin_init);

// ── Plugin metadata ───────────────────────────────────────────────────────────
// Required boilerplate that VPP uses to identify and load this plugin.
VLIB_PLUGIN_REGISTER () = {
    .version     = "1.0.0",
    .description = "Custom TAP start node plugin - reads from mytap0 TAP interface",
};
