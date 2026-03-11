// ─────────────────────────────────────────────────────────────────────────────
// my_start_node.c
//
// This is our custom VPP INPUT node.
// "Input node" means VPP calls this node on its own, with no upstream node.
// It is the very beginning of our packet pipeline.
//
// What it does:
//   1. Reads raw Ethernet frames from a Linux TAP interface
//   2. Wraps each frame in a VPP buffer
//   3. Passes the buffers to the next node (your-parser-node)
//
// Pipeline:
//   my-start-node
//        ↓
//   your-parser-node
//        ↓
//   your-firewall-node
//        ↓
//   your-output-node
// ─────────────────────────────────────────────────────────────────────────────

#include <unistd.h>             // read()
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>         // packet generator helpers
#include <vppinfra/error.h>     // VPP error macros

#include "my_start_node.h"      // our plugin's global state + node declaration
#include "tap_utils.h"          // tap_open_interface(), tap_close_interface()

// ─────────────────────────────────────────────────────────────────────────────
// Error counter definitions
//
// VPP lets each node define named counters.
// You can see them with:  vppctl show errors
// ─────────────────────────────────────────────────────────────────────────────

// Macro trick: list all errors once, generate both enum and strings from it
#define foreach_my_start_error          \
  _ (PROCESSED, "Packets processed")   \
  _ (NO_BUFFER, "Buffer alloc failed") \
  _ (TAP_READ_ERR, "TAP read error")

// This creates an enum:  MY_START_ERROR_PROCESSED,
//                        MY_START_ERROR_NO_BUFFER, etc.
typedef enum
{
#define _ (sym, str) MY_START_ERROR_##sym,
  foreach_my_start_error
#undef _
    MY_START_N_ERRORS,
} my_start_error_t;

// This creates an array of strings for the VPP UI
static char *my_start_error_strings[] = {
#define _ (sym, str) str,
  foreach_my_start_error
#undef _
};

// ─────────────────────────────────────────────────────────────────────────────
// Next node indices
//
// These map to the .next_nodes[] array at the bottom of this file.
// When we call vlib_get_next_frame(..., next_index, ...) we use these.
// ─────────────────────────────────────────────────────────────────────────────
typedef enum
{
    MY_START_NEXT_PARSER,   // index 0 → "your-parser-node"
    MY_START_NEXT_DROP,     // index 1 → "error-drop"
    MY_START_N_NEXT,        // total count (must be last)
} my_start_next_t;

// ─────────────────────────────────────────────────────────────────────────────
// Trace record
//
// When tracing is enabled (vppctl trace add my-start-node 10),
// VPP stores one of these structs per packet and prints it later.
// ─────────────────────────────────────────────────────────────────────────────
typedef struct
{
    u32 sw_if_index;    // which interface the packet came from
    u32 next_index;     // which next node it was sent to
    u32 packet_length;  // how many bytes in the packet
    u8  packet_data[32];// first 32 bytes of the packet (for inspection)
} my_start_trace_t;

// This function formats the trace record for display
static u8 *
format_my_start_trace (u8 *s, va_list *args)
{
    // VPP passes vm and node but we don't need them here, just skip them
    CLIB_UNUSED (vlib_main_t * vm)   = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

    my_start_trace_t *t = va_arg (*args, my_start_trace_t *);

    s = format (s,
                "MY-START: sw_if_index=%d next=%d len=%d\n"
                "  first 32 bytes: %U",
                t->sw_if_index,
                t->next_index,
                t->packet_length,
                format_hex_bytes, t->packet_data, sizeof (t->packet_data));
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// my_start_node_fn  ← the main node function
//
// VPP calls this repeatedly in its main loop (because node type = INPUT).
// Each call should read as many packets as available and push them forward.
// ─────────────────────────────────────────────────────────────────────────────
static uword
my_start_node_fn (vlib_main_t        *vm,
                  vlib_node_runtime_t *node,
                  vlib_frame_t        *frame)
{
    // Get our plugin's global state (tap_fd, counters, etc.)
    my_start_main_t *msm = &my_start_main;

    // If TAP interface isn't open yet, nothing to do
    if (msm->tap_fd < 0)
        return 0;

    // ── Step 1: Read packets from TAP into VPP buffers ───────────────────────

    // bi[] = buffer index array.
    // VPP doesn't give you raw pointers; instead it gives you indices.
    // Use vlib_get_buffer(vm, bi[i]) to convert index → pointer.
    u32 bi[VLIB_FRAME_SIZE];    // max 256 packets per call
    u32 n_rx = 0;               // how many packets we actually got

    // Read up to VLIB_FRAME_SIZE packets from the TAP fd
    while (n_rx < VLIB_FRAME_SIZE)
    {
        // Ask VPP to allocate 1 fresh buffer for us
        u32 new_bi;
        if (vlib_buffer_alloc (vm, &new_bi, 1) != 1)
        {
            // VPP is out of buffers - very unusual, but handle it gracefully
            vlib_node_increment_counter (vm, node->node_index,
                                         MY_START_ERROR_NO_BUFFER, 1);
            break;  // stop reading, try again next cycle
        }

        // Convert the buffer index to an actual pointer
        vlib_buffer_t *b = vlib_get_buffer (vm, new_bi);

        // vlib_buffer_get_current(b) = pointer to where we should write data
        // VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES = max buffer size (usually 2048)
        int bytes_read = read (msm->tap_fd,
                               vlib_buffer_get_current (b),
                               VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES);

        if (bytes_read <= 0)
        {
            // No packet available right now (O_NONBLOCK returns immediately)
            // Free the buffer we allocated since we won't use it
            vlib_buffer_free (vm, &new_bi, 1);
            break;  // no more packets waiting, exit the read loop
        }

        // Tell VPP how many bytes are valid in this buffer
        b->current_length = bytes_read;

        // Tag the buffer with which interface it "came from"
        // sw_if_index = software interface index, 0 = first interface
        // Change this if you want to track a specific VPP interface
        vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
        vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0; // ~0 = "not decided yet"

        // Save the buffer index in our local array
        bi[n_rx] = new_bi;
        n_rx++;
        msm->total_rx_packets++;
    }

    // If we got zero packets, nothing to do this cycle
    if (n_rx == 0)
        return 0;

    // ── Step 2: Enqueue all packets to the next node (parser) ────────────────

    // We'll send everything to the parser node
    u32 next_index = MY_START_NEXT_PARSER;

    // from = pointer to our buffer index array
    // n_left_from = how many buffers remain to process
    u32 *from       = bi;
    u32  n_left_from = n_rx;

    while (n_left_from > 0)
    {
        // to_next = where we write buffer indices for the next node's frame
        // n_left_to_next = how many slots are free in the next frame
        u32 *to_next;
        u32  n_left_to_next;

        // Get a "frame" (batch slot) from the next node
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        // ── Fast path: process 4 packets at a time ──────────────────────────
        // This is a standard VPP pattern for high throughput.
        // Prefetching means: "load this memory into CPU cache early"
        // so by the time we need it, it's already fast to access.
        while (n_left_from >= 4 && n_left_to_next >= 4)
        {
            u32 bi0, bi1, bi2, bi3;
            vlib_buffer_t *b0, *b1, *b2, *b3;

            // Prefetch the buffers we'll process 2 iterations from now
            vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
            vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

            // Pick up 4 buffer indices from our source array
            bi0 = from[0];
            bi1 = from[1];
            bi2 = from[2];
            bi3 = from[3];
            from          += 4;
            n_left_from   -= 4;

            // Write those 4 indices into the next node's frame
            to_next[0] = bi0;
            to_next[1] = bi1;
            to_next[2] = bi2;
            to_next[3] = bi3;
            to_next        += 4;
            n_left_to_next -= 4;

            // Get pointers so we can read/write the actual buffer data
            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);
            b2 = vlib_get_buffer (vm, bi2);
            b3 = vlib_get_buffer (vm, bi3);

            // Add trace records if tracing is enabled for this node
            // VLIB_BUFFER_IS_TRACED flag is set by "vppctl trace add ..."
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                my_start_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index  = vnet_buffer (b0)->sw_if_index[VLIB_RX];
                t->next_index   = next_index;
                t->packet_length = b0->current_length;
                clib_memcpy (t->packet_data,
                             vlib_buffer_get_current (b0),
                             clib_min (sizeof (t->packet_data),
                                       b0->current_length));
            }
            if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                my_start_trace_t *t =
                    vlib_add_trace (vm, node, b1, sizeof (*t));
                t->sw_if_index  = vnet_buffer (b1)->sw_if_index[VLIB_RX];
                t->next_index   = next_index;
                t->packet_length = b1->current_length;
                clib_memcpy (t->packet_data,
                             vlib_buffer_get_current (b1),
                             clib_min (sizeof (t->packet_data),
                                       b1->current_length));
            }
            // (trace for b2 and b3 omitted for brevity - same pattern)

            // (no per-packet logic needed here since parser does that)
        }

        // ── Slow path: process 1 packet at a time (leftover packets) ────────
        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t *b0;

            bi0           = from[0];
            from         += 1;
            n_left_from  -= 1;

            to_next[0]     = bi0;
            to_next       += 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                my_start_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index  = vnet_buffer (b0)->sw_if_index[VLIB_RX];
                t->next_index   = next_index;
                t->packet_length = b0->current_length;
                clib_memcpy (t->packet_data,
                             vlib_buffer_get_current (b0),
                             clib_min (sizeof (t->packet_data),
                                       b0->current_length));
            }
        }

        // Release the frame back to the next node - this is what actually
        // "sends" the packets forward in the graph
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    // Increment the "processed" counter by how many packets we handled
    vlib_node_increment_counter (vm, node->node_index,
                                 MY_START_ERROR_PROCESSED, n_rx);

    return n_rx;  // tell VPP how many vectors (packets) we processed
}

// ─────────────────────────────────────────────────────────────────────────────
// Node registration
//
// This macro registers our node with VPP.
// VPP reads this at startup and adds the node to the graph.
// ─────────────────────────────────────────────────────────────────────────────
VLIB_REGISTER_NODE (my_start_node) = {
    .function     = my_start_node_fn,   // the function VPP calls
    .name         = "my-start-node",    // name used in vppctl commands
    .vector_size  = sizeof (u32),       // each element in a frame is a u32 (buffer index)
    .format_trace = format_my_start_trace,

    // VLIB_NODE_TYPE_INPUT = this node generates its own packets (no upstream)
    // VPP will call it automatically in its main polling loop
    .type  = VLIB_NODE_TYPE_INPUT,

    // Start in POLLING mode - VPP calls us every loop iteration
    // You can change to INTERRUPT mode later for event-driven operation
    .state = VLIB_NODE_STATE_POLLING,

    .n_errors      = MY_START_N_ERRORS,
    .error_strings = my_start_error_strings,

    // Define which nodes come after us in the graph
    .n_next_nodes = MY_START_N_NEXT,
    .next_nodes   = {
        [MY_START_NEXT_PARSER] = "your-parser-node",    // normal path
        [MY_START_NEXT_DROP]   = "error-drop",          // discard bad packets
    },
};
