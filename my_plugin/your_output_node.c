// ─────────────────────────────────────────────────────────────────────────────
// your_output_node.c
//
// OUTPUT NODE - Last node in our pipeline.
//
// Receives allowed IPv4 packets from the firewall node.
// For this example, it simply logs the packet and frees the buffer.
// In a real project you would:
//   - Write the packet back to a TAP interface (Linux gets it)
//   - Forward it to ip4-lookup for routing
//   - Send it out a physical interface
//
// Pipeline position:
//   your-firewall-node → [YOU ARE HERE] → (end / discard)
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <unistd.h>    // write() - to send packets back via TAP
#include <vppinfra/error.h>

#include "my_start_node.h"  // we need tap_fd to write packets back out

// ── Error counters ────────────────────────────────────────────────────────────
#define foreach_output_error                        \
  _ (SENT,       "Packets sent to TAP output")      \
  _ (WRITE_FAIL, "TAP write failed")                \
  _ (TOO_SHORT,  "Packet too short")

typedef enum
{
#define _ (sym, str) OUTPUT_ERROR_##sym,
  foreach_output_error
#undef _
    OUTPUT_N_ERRORS,
} output_error_t;

static char *output_error_strings[] = {
#define _ (sym, str) str,
  foreach_output_error
#undef _
};

// ── Next nodes ────────────────────────────────────────────────────────────────
// Output node is a "terminal" node - it doesn't send to anything after it.
// We still need error-drop for error cases.
typedef enum
{
    OUTPUT_NEXT_DROP,   // → error-drop (only used on errors)
    OUTPUT_N_NEXT,
} output_next_t;

// ── Trace record ──────────────────────────────────────────────────────────────
typedef struct
{
    u32 packet_length;
    u32 src_ip;
    u32 dst_ip;
} output_trace_t;

static u8 *
format_output_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm)   = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    output_trace_t *t = va_arg (*args, output_trace_t *);

    s = format (s, "OUTPUT: len=%d src=%U dst=%U",
                t->packet_length,
                format_ip4_address, &t->src_ip,
                format_ip4_address, &t->dst_ip);
    return s;
}

// ── Node function ─────────────────────────────────────────────────────────────
static uword
your_output_node_fn (vlib_main_t        *vm,
                     vlib_node_runtime_t *node,
                     vlib_frame_t        *frame)
{
    my_start_main_t *msm = &my_start_main;  // get tap_fd from plugin state

    u32  n_left_from = frame->n_vectors;
    u32 *from        = vlib_frame_vector_args (frame);

    u32 sent       = 0;
    u32 write_fail = 0;
    u32 too_short  = 0;

    // Collect all buffer indices so we can free them at the end
    u32 to_free[VLIB_FRAME_SIZE];
    u32 n_to_free = 0;

    while (n_left_from > 0)
    {
        u32 bi0;
        vlib_buffer_t *b0;

        bi0 = from[0];
        from++;
        n_left_from--;

        b0 = vlib_get_buffer (vm, bi0);

        // ── Optional: write packet back to TAP so Linux sees it ──────────────
        // This is useful for loopback testing or forwarding to Linux userspace.
        // The firewall already stripped the Ethernet header in the parser,
        // so we are writing raw IPv4 packets here.
        if (msm->tap_fd >= 0 && b0->current_length >= sizeof (ip4_header_t))
        {
            // write() sends the data to the TAP interface
            // The return value is how many bytes were written (-1 = error)
            int written = write (msm->tap_fd,
                                 vlib_buffer_get_current (b0),
                                 b0->current_length);
            if (written < 0)
                write_fail++;
            else
                sent++;
        }
        else if (b0->current_length < sizeof (ip4_header_t))
        {
            too_short++;
        }
        else
        {
            // TAP not open, just count it as sent (or log/discard as you wish)
            sent++;
        }

        // Trace
        if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
        {
            output_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->packet_length  = b0->current_length;

            if (b0->current_length >= sizeof (ip4_header_t))
            {
                ip4_header_t *ip = vlib_buffer_get_current (b0);
                t->src_ip = ip->src_address.as_u32;
                t->dst_ip = ip->dst_address.as_u32;
            }
        }

        // Queue this buffer for freeing after the loop
        to_free[n_to_free++] = bi0;
    }

    // Free all buffers at once (more efficient than one at a time)
    if (n_to_free > 0)
        vlib_buffer_free (vm, to_free, n_to_free);

    vlib_node_increment_counter (vm, node->node_index,
                                 OUTPUT_ERROR_SENT,       sent);
    vlib_node_increment_counter (vm, node->node_index,
                                 OUTPUT_ERROR_WRITE_FAIL, write_fail);
    vlib_node_increment_counter (vm, node->node_index,
                                 OUTPUT_ERROR_TOO_SHORT,  too_short);

    return frame->n_vectors;
}

// ── Node registration ─────────────────────────────────────────────────────────
VLIB_REGISTER_NODE (your_output_node) = {
    .function     = your_output_node_fn,
    .name         = "your-output-node",
    .vector_size  = sizeof (u32),
    .format_trace = format_output_trace,
    .type         = VLIB_NODE_TYPE_INTERNAL,

    .n_errors      = OUTPUT_N_ERRORS,
    .error_strings = output_error_strings,

    // Terminal node - the only "next" is error-drop for error cases
    .n_next_nodes = OUTPUT_N_NEXT,
    .next_nodes   = {
        [OUTPUT_NEXT_DROP] = "error-drop",
    },
};
