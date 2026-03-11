// ─────────────────────────────────────────────────────────────────────────────
// your_firewall_node.c
//
// FIREWALL NODE - Third node in our pipeline.
//
// Receives raw IPv4 packets (Ethernet header already stripped by parser).
// Applies simple rules:
//   - Block packets from a hardcoded "bad" source IP
//   - Allow everything else → send to output node
//
// Pipeline position:
//   your-parser-node → [YOU ARE HERE] → your-output-node
// ─────────────────────────────────────────────────────────────────────────────

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>   // ip4_header_t - the IPv4 header struct
#include <vppinfra/error.h>

// ── Simple rule: block this source IP address ────────────────────────────────
// 192.168.1.100 in host byte order
// Use clib_host_to_net_u32() if you want to compare in network byte order.
// For simplicity we'll compare in network byte order using the macro below.
//
// To change the blocked IP, change these numbers (they represent 192.168.1.100):
#define BLOCKED_IP_BYTE0 192
#define BLOCKED_IP_BYTE1 168
#define BLOCKED_IP_BYTE2   1
#define BLOCKED_IP_BYTE3 100

// ── Error counters ────────────────────────────────────────────────────────────
#define foreach_firewall_error               \
  _ (ALLOWED,     "Packets allowed")         \
  _ (BLOCKED,     "Packets blocked by rule") \
  _ (TOO_SHORT,   "Packet too short for IP")

typedef enum
{
#define _ (sym, str) FIREWALL_ERROR_##sym,
  foreach_firewall_error
#undef _
    FIREWALL_N_ERRORS,
} firewall_error_t;

static char *firewall_error_strings[] = {
#define _ (sym, str) str,
  foreach_firewall_error
#undef _
};

// ── Next nodes ────────────────────────────────────────────────────────────────
typedef enum
{
    FIREWALL_NEXT_OUTPUT,   // → your-output-node (allowed packets)
    FIREWALL_NEXT_DROP,     // → error-drop (blocked packets)
    FIREWALL_N_NEXT,
} firewall_next_t;

// ── Trace record ──────────────────────────────────────────────────────────────
typedef struct
{
    u32 src_ip;     // source IP address (in network byte order)
    u32 dst_ip;     // destination IP address (in network byte order)
    u32 next_index; // ALLOWED or BLOCKED
} firewall_trace_t;

static u8 *
format_firewall_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm)   = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    firewall_trace_t *t = va_arg (*args, firewall_trace_t *);

    s = format (s, "FIREWALL: src=%U dst=%U %s",
                format_ip4_address, &t->src_ip,
                format_ip4_address, &t->dst_ip,
                t->next_index == FIREWALL_NEXT_OUTPUT ? "ALLOW" : "BLOCK");
    return s;
}

// ── Helper: check if an IP matches our blocked IP ────────────────────────────
// ip4_header_t stores IPs as a union; src_address.as_u8[] gives us bytes.
static inline int
is_blocked_ip (ip4_header_t *ip)
{
    return (ip->src_address.as_u8[0] == BLOCKED_IP_BYTE0 &&
            ip->src_address.as_u8[1] == BLOCKED_IP_BYTE1 &&
            ip->src_address.as_u8[2] == BLOCKED_IP_BYTE2 &&
            ip->src_address.as_u8[3] == BLOCKED_IP_BYTE3);
}

// ── Node function ─────────────────────────────────────────────────────────────
static uword
your_firewall_node_fn (vlib_main_t        *vm,
                       vlib_node_runtime_t *node,
                       vlib_frame_t        *frame)
{
    u32  n_left_from = frame->n_vectors;
    u32 *from        = vlib_frame_vector_args (frame);

    u32 allowed   = 0;
    u32 blocked   = 0;
    u32 too_short = 0;

    while (n_left_from > 0)
    {
        u32 bi0;
        vlib_buffer_t *b0;
        ip4_header_t  *ip0;
        u32 next0 = FIREWALL_NEXT_OUTPUT;  // default: allow

        bi0 = from[0];
        from++;
        n_left_from--;

        b0 = vlib_get_buffer (vm, bi0);

        // ── Check the packet is at least as long as an IPv4 header ───────────
        // Minimum IPv4 header = 20 bytes
        if (b0->current_length < sizeof (ip4_header_t))
        {
            too_short++;
            next0 = FIREWALL_NEXT_DROP;
            goto trace_and_enqueue;
        }

        // ── Get the IPv4 header pointer ───────────────────────────────────────
        // At this point, the parser already advanced past the Ethernet header,
        // so current_data points directly at the IPv4 header.
        ip0 = vlib_buffer_get_current (b0);

        // ── Apply firewall rule: block packets from BLOCKED_IP ────────────────
        if (is_blocked_ip (ip0))
        {
            blocked++;
            next0 = FIREWALL_NEXT_DROP;
        }
        else
        {
            allowed++;
            next0 = FIREWALL_NEXT_OUTPUT;
        }

    trace_and_enqueue:
        if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
        {
            firewall_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            // Store IPs as u32 for display via format_ip4_address
            if (b0->current_length >= sizeof (ip4_header_t))
            {
                ip4_header_t *ip = vlib_buffer_get_current (b0);
                t->src_ip = ip->src_address.as_u32;
                t->dst_ip = ip->dst_address.as_u32;
            }
            else
            {
                t->src_ip = 0;
                t->dst_ip = 0;
            }
            t->next_index = next0;
        }

        vlib_set_next_node_buffer (vm, node, bi0, next0);
    }

    vlib_node_increment_counter (vm, node->node_index,
                                 FIREWALL_ERROR_ALLOWED,   allowed);
    vlib_node_increment_counter (vm, node->node_index,
                                 FIREWALL_ERROR_BLOCKED,   blocked);
    vlib_node_increment_counter (vm, node->node_index,
                                 FIREWALL_ERROR_TOO_SHORT, too_short);

    return frame->n_vectors;
}

// ── Node registration ─────────────────────────────────────────────────────────
VLIB_REGISTER_NODE (your_firewall_node) = {
    .function     = your_firewall_node_fn,
    .name         = "your-firewall-node",
    .vector_size  = sizeof (u32),
    .format_trace = format_firewall_trace,
    .type         = VLIB_NODE_TYPE_INTERNAL,

    .n_errors      = FIREWALL_N_ERRORS,
    .error_strings = firewall_error_strings,

    .n_next_nodes = FIREWALL_N_NEXT,
    .next_nodes   = {
        [FIREWALL_NEXT_OUTPUT] = "your-output-node",
        [FIREWALL_NEXT_DROP]   = "error-drop",
    },
};
