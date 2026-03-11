// ─────────────────────────────────────────────────────────────────────────────
// your_parser_node.c
//
// PARSER NODE - Second node in our pipeline.
//
// Receives raw Ethernet frames from my-start-node.
// Looks at each packet and decides:
//   - Is this IPv4? → send to firewall
//   - Anything else? → drop it
//
// Pipeline position:
//   my-start-node → [YOU ARE HERE] → your-firewall-node
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>  // ethernet_header_t, Ethernet type codes
#include <vppinfra/error.h>

// ── Error counters ───────────────────────────────────────────────────────────
#define foreach_parser_error            \
  _ (PARSED_OK,    "Packets parsed OK") \
  _ (NOT_IPV4,     "Non-IPv4 dropped")  \
  _ (TOO_SHORT,    "Packet too short")

typedef enum
{
#define _ (sym, str) PARSER_ERROR_##sym,
  foreach_parser_error
#undef _
    PARSER_N_ERRORS,
} parser_error_t;

static char *parser_error_strings[] = {
#define _ (sym, str) str,
  foreach_parser_error
#undef _
};

// ── Next nodes ───────────────────────────────────────────────────────────────
typedef enum
{
    PARSER_NEXT_FIREWALL,  // → your-firewall-node (IPv4 packets)
    PARSER_NEXT_DROP,      // → error-drop (unknown/bad packets)
    PARSER_N_NEXT,
} parser_next_t;

// ── Trace record ─────────────────────────────────────────────────────────────
typedef struct
{
    u16 ether_type;   // the EtherType field from the Ethernet header
    u32 next_index;   // which next node we chose
} parser_trace_t;

static u8 *
format_parser_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm)   = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    parser_trace_t *t = va_arg (*args, parser_trace_t *);

    s = format (s, "PARSER: ethertype=0x%04x next=%d",
                t->ether_type, t->next_index);
    return s;
}

// ── Node function ─────────────────────────────────────────────────────────────
static uword
your_parser_node_fn (vlib_main_t        *vm,
                     vlib_node_runtime_t *node,
                     vlib_frame_t        *frame)
{
    // frame->n_vectors = how many packets arrived this call
    u32  n_left_from = frame->n_vectors;

    // vlib_frame_vector_args() returns pointer to the array of buffer indices
    u32 *from = vlib_frame_vector_args (frame);

    // Counters - we'll add these to VPP's error counters at the end
    u32 parsed_ok = 0;
    u32 not_ipv4  = 0;
    u32 too_short = 0;

    // Process one packet at a time (you can add a 4-at-a-time fast path later)
    while (n_left_from > 0)
    {
        u32 bi0;
        vlib_buffer_t *b0;
        u32 next0 = PARSER_NEXT_DROP;  // default: drop unless we say otherwise
        u16 ether_type;

        // Get the next buffer index from the incoming frame
        bi0 = from[0];
        from++;
        n_left_from--;

        // Get pointer to the buffer
        b0 = vlib_get_buffer (vm, bi0);

        // ── Check packet is long enough to have an Ethernet header ───────────
        // An Ethernet header is 14 bytes: 6 dst MAC + 6 src MAC + 2 EtherType
        if (b0->current_length < sizeof (ethernet_header_t))
        {
            too_short++;
            next0 = PARSER_NEXT_DROP;
            goto trace_and_enqueue;
        }

        // ── Read the EtherType field from the Ethernet header ─────────────────
        // The Ethernet header is at the start of the packet data.
        // ethernet_header_t is defined by VPP's ethernet library.
        ethernet_header_t *eth = vlib_buffer_get_current (b0);

        // clib_net_to_host_u16 converts from network byte order (big-endian)
        // to host byte order - necessary because x86 CPUs are little-endian
        ether_type = clib_net_to_host_u16 (eth->type);

        // ── Route the packet based on EtherType ──────────────────────────────
        if (ether_type == ETHERNET_TYPE_IP4)
        {
            // 0x0800 = IPv4
            // Move past the Ethernet header so the next node sees raw IP
            vlib_buffer_advance (b0, sizeof (ethernet_header_t));
            next0 = PARSER_NEXT_FIREWALL;
            parsed_ok++;
        }
        else
        {
            // Not IPv4 - we don't handle ARP, IPv6, etc. in this example
            not_ipv4++;
            next0 = PARSER_NEXT_DROP;
        }

    trace_and_enqueue:
        // Add trace if enabled
        if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
        {
            parser_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->ether_type = ether_type;
            t->next_index = next0;
        }

        // Send this packet to the chosen next node
        // vlib_set_next_node_buffer sets where this specific buffer goes
        vlib_set_next_node_buffer (vm, node, bi0, next0);
    }

    // Flush all the packets we routed to their next nodes
    vlib_node_increment_counter (vm, node->node_index,
                                 PARSER_ERROR_PARSED_OK, parsed_ok);
    vlib_node_increment_counter (vm, node->node_index,
                                 PARSER_ERROR_NOT_IPV4,  not_ipv4);
    vlib_node_increment_counter (vm, node->node_index,
                                 PARSER_ERROR_TOO_SHORT, too_short);

    return frame->n_vectors;
}

// ── Node registration ─────────────────────────────────────────────────────────
VLIB_REGISTER_NODE (your_parser_node) = {
    .function     = your_parser_node_fn,
    .name         = "your-parser-node",
    .vector_size  = sizeof (u32),
    .format_trace = format_parser_trace,
    .type         = VLIB_NODE_TYPE_INTERNAL,  // INTERNAL = receives packets from another node

    .n_errors      = PARSER_N_ERRORS,
    .error_strings = parser_error_strings,

    .n_next_nodes = PARSER_N_NEXT,
    .next_nodes   = {
        [PARSER_NEXT_FIREWALL] = "your-firewall-node",
        [PARSER_NEXT_DROP]     = "error-drop",
    },
};
