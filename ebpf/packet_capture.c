/*
 * eBPF packet capture program for Network Feature Extractor
 * 
 * This program attaches to network interfaces to capture and analyze packet data,
 * supporting both IPv4 and IPv6 traffic, and multiple transport protocols.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define constants
#define MAX_FLOWS 65536    // Maximum number of flows to track
#define FLOW_CLEANUP_SEC 10 // Flow cleanup interval in seconds
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMP 1
#define IP_PROTO_ICMPV6 58
#define IP_PROTO_SCTP 132
#define IP_PROTO_DCCP 33
#define IP_PROTO_RSVP 46
#define IP_PROTO_QUIC 17    // QUIC uses UDP, so we identify it separately

// Add IPv6 extension header type definitions
#define IPV6_EXT_HOP_BY_HOP 0
#define IPV6_EXT_ROUTING 43
#define IPV6_EXT_FRAGMENT 44
#define IPV6_EXT_ESP 50
#define IPV6_EXT_AUTH 51
#define IPV6_EXT_DEST_OPTS 60
#define IPV6_EXT_MOBILITY 135

/* 
 * Flow key structure to uniquely identify a flow
 * For IPv4, the high bytes of addresses are zeroed
 */
struct flow_key {
    __u8 ip_version;       // 4 or 6
    __u8 protocol;         // Transport protocol
    __u32 src_addr[4];     // Source IP address (IPv4 or IPv6)
    __u32 dst_addr[4];     // Destination IP address (IPv4 or IPv6)
    __u16 src_port;        // Source port
    __u16 dst_port;        // Destination port
};

/*
 * Packet metadata sent to user space for feature extraction
 */
struct packet_metadata {
    struct flow_key key;           // Flow key
    __u32 timestamp_ns;            // Packet timestamp (nanoseconds)
    __u32 size;                    // Packet size in bytes
    __u16 header_size;             // Header size in bytes
    __u8 direction;                // Packet direction (0=forward, 1=backward)
    __u8 flags;                    // TCP flags if applicable
    __u16 window_size;             // TCP window size if applicable
    __u16 mss;                     // TCP MSS if present
    __u8 sampling_rate;            // Current sampling rate (for user-space awareness)
};

/*
 * Flow state stored in kernel space
 */
struct flow_state {
    __u64 last_update;             // Last update timestamp
    __u32 forward_packets;         // Forward packet count
    __u32 backward_packets;        // Backward packet count
    __u32 forward_bytes;           // Forward byte count
    __u32 backward_bytes;          // Backward byte count
};

// BPF maps

// Flow tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_map SEC(".maps");

// Ring buffer for sending metadata to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} metadata_ringbuf SEC(".maps");

// Configuration and statistics maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Enum for statistics indices
enum {
    STAT_PROCESSED_PACKETS,
    STAT_PROCESSED_BYTES,
    STAT_DROPPED_PACKETS,
    STAT_SAMPLED_PACKETS,
    STAT_IPV4_PACKETS,
    STAT_IPV6_PACKETS,
    STAT_UNKNOWN_PACKETS,
    STAT_ERROR_PACKETS
};

// Enum for config indices
enum {
    CONFIG_SAMPLING_ENABLED,
    CONFIG_SAMPLING_RATE,
    CONFIG_CAPTURE_TCP,
    CONFIG_CAPTURE_UDP,
    CONFIG_CAPTURE_ICMP,
    CONFIG_CAPTURE_OTHER
};

// Function to update flow state
static inline void update_flow(struct flow_key *key, struct flow_state *state, 
                              __u8 direction, __u32 size, __u64 timestamp) {
    if (direction == 0) {
        state->forward_packets++;
        state->forward_bytes += size;
    } else {
        state->backward_packets++;
        state->backward_bytes += size;
    }
    state->last_update = timestamp;
}

// Function to determine if a packet should be sampled
static inline int should_sample() {
    __u32 idx = CONFIG_SAMPLING_ENABLED;
    __u32 enabled = 0;
    __u32 *value = bpf_map_lookup_elem(&config_map, &idx);
    if (value && *value) {
        enabled = 1;
    } else {
        return 1; // If sampling not enabled, process all packets
    }
    
    if (enabled) {
        idx = CONFIG_SAMPLING_RATE;
        value = bpf_map_lookup_elem(&config_map, &idx);
        if (value) {
            __u32 rate = *value;
            // Generate a random value using jiffies
            __u32 rand = bpf_get_prandom_u32();
            // Fixed: Properly scale the comparison
            // rate is 0-100 (percentage), scale to full u32 range
            __u64 threshold = (__u64)rate * 0xFFFFFFFF / 100;
            // Sample if random value is less than the scaled threshold
            return (rand < threshold);
        }
    }
    
    return 1; // Default to processing all packets
}

// Function to update statistics
static inline void update_statistics(int stat_idx, __u64 value) {
    __u64 *stat = bpf_map_lookup_elem(&stats_map, &stat_idx);
    if (stat) {
        __sync_fetch_and_add(stat, value);
    }
}

// Function to parse IPv6 extension headers and find the transport header
static inline void *parse_ipv6_extensions(struct ipv6hdr *ip6, void *data_end, __u8 *next_hdr) {
    // Initial bounds check
    if ((void *)(ip6 + 1) > data_end) {
        return NULL;
    }
    
    void *current = ip6 + 1;
    __u8 current_hdr = ip6->nexthdr;
    
    // Set the initial next header value
    *next_hdr = current_hdr;
    
    // Process up to 8 extension headers (limit to prevent loops)
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        // Check if we've found a non-extension header
        if (current_hdr != IPV6_EXT_HOP_BY_HOP && 
            current_hdr != IPV6_EXT_ROUTING && 
            current_hdr != IPV6_EXT_FRAGMENT && 
            current_hdr != IPV6_EXT_DEST_OPTS && 
            current_hdr != IPV6_EXT_MOBILITY) {
            break;
        }
        
        // Verify we have enough data for extension header
        if (current + 2 > data_end) {
            return NULL;
        }
        
        // Extension header layout: next header (1 byte), header length (1 byte), then data
        __u8 *ext_hdr = (__u8 *)current;
        __u8 ext_len = ext_hdr[1];
        
        // Update current header and pointer
        current_hdr = ext_hdr[0];
        current = ext_hdr + (ext_len + 1) * 8;  // Length is in 8-byte units excluding first 8 bytes
        
        // Boundary check
        if (current > data_end) {
            return NULL;
        }
    }
    
    // Return the next header type and pointer
    *next_hdr = current_hdr;
    return current;
}

// XDP program entry point
SEC("xdp")
int xdp_packet_capture(struct xdp_md *ctx) {
    // Access packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Verify packet has enough data for Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        update_statistics(STAT_ERROR_PACKETS, 1);
        return XDP_PASS; // Pass packet to kernel
    }
    
    // Skip non-IP packets
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type != ETH_P_IP && eth_type != ETH_P_IPV6) {
        update_statistics(STAT_UNKNOWN_PACKETS, 1);
        return XDP_PASS;
    }
    
    // Apply sampling if enabled
    if (!should_sample()) {
        update_statistics(STAT_DROPPED_PACKETS, 1);
        return XDP_PASS;
    }
    
    // Initialize flow key
    struct flow_key key = {};
    __u8 protocol = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 flags = 0;
    __u16 window_size = 0;
    __u16 header_size = sizeof(struct ethhdr);
    
    // Process IPv4 packets
    if (eth_type == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        
        // Check if we have a complete IPv4 header
        if ((void *)(ip + 1) > data_end) {
            update_statistics(STAT_ERROR_PACKETS, 1);
            return XDP_PASS;
        }
        
        // Set IPv4 flow key fields
        key.ip_version = 4;
        key.protocol = ip->protocol;
        key.src_addr[0] = ip->saddr;
        key.dst_addr[0] = ip->daddr;
        
        // Update header size
        header_size += (ip->ihl * 4);
        
        // Get protocol-specific information
        switch (ip->protocol) {
            case IP_PROTO_TCP: {
                // Access TCP header
                struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
                if ((void *)(tcp + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                key.src_port = bpf_ntohs(tcp->source);
                key.dst_port = bpf_ntohs(tcp->dest);
                flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | 
                        (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
                window_size = bpf_ntohs(tcp->window);
                header_size += (tcp->doff * 4);
                break;
            }
            case IP_PROTO_UDP: {
                // Access UDP header
                struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
                if ((void *)(udp + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                key.src_port = bpf_ntohs(udp->source);
                key.dst_port = bpf_ntohs(udp->dest);
                header_size += sizeof(struct udphdr);
                break;
            }
            case IP_PROTO_ICMP: {
                // Access ICMP header
                struct icmphdr *icmp = (struct icmphdr *)((void *)ip + (ip->ihl * 4));
                if ((void *)(icmp + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                // ICMP doesn't have ports, using type/code as ports for keying
                key.src_port = icmp->type;
                key.dst_port = icmp->code;
                header_size += sizeof(struct icmphdr);
                break;
            }
            default:
                // For other protocols, we may not be able to determine ports
                break;
        }
        
        update_statistics(STAT_IPV4_PACKETS, 1);
    }
    // Process IPv6 packets
    else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        
        // Check if we have a complete IPv6 header
        if ((void *)(ip6 + 1) > data_end) {
            update_statistics(STAT_ERROR_PACKETS, 1);
            return XDP_PASS;
        }
        
        // Set IPv6 flow key fields
        key.ip_version = 6;
        key.protocol = ip6->nexthdr;
        
        // Copy IPv6 addresses (4 32-bit words each)
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            key.src_addr[i] = ip6->saddr.in6_u.u6_addr32[i];
            key.dst_addr[i] = ip6->daddr.in6_u.u6_addr32[i];
        }
        
        // Update header size
        header_size += sizeof(struct ipv6hdr);
        
        // Parse IPv6 extension headers and find transport header
        __u8 next_header = ip6->nexthdr;
        void *transport_header = parse_ipv6_extensions(ip6, data_end, &next_header);
        
        // If extension header parsing failed, pass packet along
        if (!transport_header) {
            update_statistics(STAT_ERROR_PACKETS, 1);
            return XDP_PASS;
        }
        
        // Update protocol after parsing extensions
        key.protocol = next_header;
        
        // Get protocol-specific information
        switch (next_header) {
            case IP_PROTO_TCP: {
                // Access TCP header
                struct tcphdr *tcp = (struct tcphdr *)transport_header;
                if ((void *)(tcp + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                key.src_port = bpf_ntohs(tcp->source);
                key.dst_port = bpf_ntohs(tcp->dest);
                flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | 
                        (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
                window_size = bpf_ntohs(tcp->window);
                header_size += (tcp->doff * 4);
                break;
            }
            case IP_PROTO_UDP: {
                // Access UDP header
                struct udphdr *udp = (struct udphdr *)transport_header;
                if ((void *)(udp + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                key.src_port = bpf_ntohs(udp->source);
                key.dst_port = bpf_ntohs(udp->dest);
                header_size += sizeof(struct udphdr);
                break;
            }
            case IP_PROTO_ICMPV6: {
                // Access ICMPv6 header
                struct icmp6hdr *icmp6 = (struct icmp6hdr *)transport_header;
                if ((void *)(icmp6 + 1) > data_end) {
                    update_statistics(STAT_ERROR_PACKETS, 1);
                    return XDP_PASS;
                }
                
                // ICMPv6 doesn't have ports, using type/code as ports for keying
                key.src_port = icmp6->icmp6_type;
                key.dst_port = icmp6->icmp6_code;
                header_size += sizeof(struct icmp6hdr);
                break;
            }
            default:
                // For other protocols, we may not be able to determine ports
                break;
        }
        
        update_statistics(STAT_IPV6_PACKETS, 1);
    }
    
    // Get packet size
    __u32 packet_size = (data_end - data);
    
    // Get current timestamp
    __u64 timestamp = bpf_ktime_get_ns();
    
    // Prepare metadata to send to user space
    struct packet_metadata *meta = bpf_ringbuf_reserve(&metadata_ringbuf, sizeof(struct packet_metadata), 0);
    if (!meta) {
        update_statistics(STAT_DROPPED_PACKETS, 1);
        return XDP_PASS;
    }
    
    // Look up flow state or create a new one
    struct flow_state *state = bpf_map_lookup_elem(&flow_map, &key);
    
    // If flow doesn't exist, create a new entry with default direction as forward
    __u8 direction = 0;
    
    if (state) {
        // Determine packet direction
        if (key.ip_version == 4) {
            // For IPv4, compare source and destination addresses
            direction = (key.src_addr[0] > key.dst_addr[0]) ? 1 : 0;
            
            // If addresses are equal, use ports to determine direction
            if (key.src_addr[0] == key.dst_addr[0]) {
                direction = (key.src_port > key.dst_port) ? 1 : 0;
            }
        } else {
            // For IPv6, compare all 4 words of the address
            // This provides more accurate direction determination
            int addr_equal = 1;  // Assume addresses are equal
            int src_gt_dst = 0;
            int dst_gt_src = 0;
            
            // Compare each word in order of significance
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                if (key.src_addr[i] > key.dst_addr[i]) {
                    src_gt_dst = 1;
                    addr_equal = 0;
                    break;
                } else if (key.src_addr[i] < key.dst_addr[i]) {
                    dst_gt_src = 1;
                    addr_equal = 0;
                    break;
                }
            }
            
            // If source > destination, it's backward direction
            if (addr_equal) {
                // If addresses are equal, use ports to determine direction
                direction = (key.src_port > key.dst_port) ? 1 : 0;
            } else {
                direction = src_gt_dst ? 1 : 0;
            }
        }
    } else {
        // New flow
        struct flow_state new_state = {
            .last_update = timestamp,
            .forward_packets = 0,
            .backward_packets = 0,
            .forward_bytes = 0,
            .backward_bytes = 0
        };
        bpf_map_update_elem(&flow_map, &key, &new_state, BPF_ANY);
        
        // Look up the new state
        state = bpf_map_lookup_elem(&flow_map, &key);
        if (!state) {
            // Couldn't create or retrieve flow state
            bpf_ringbuf_discard(meta, 0);
            update_statistics(STAT_ERROR_PACKETS, 1);
            return XDP_PASS;
        }
    }
    
    // Update flow state
    update_flow(&key, state, direction, packet_size, timestamp);
    
    // Fill metadata for user space
    __builtin_memcpy(&meta->key, &key, sizeof(key));
    meta->timestamp_ns = (__u32)(timestamp & 0xFFFFFFFF); // Lower 32 bits of timestamp
    meta->size = packet_size;
    meta->header_size = header_size;
    meta->direction = direction;
    meta->flags = flags;
    meta->window_size = window_size;
    meta->mss = 0; // Would need TCP options parsing to get MSS
    
    // Get current sampling rate for user space awareness
    __u32 idx = CONFIG_SAMPLING_RATE;
    __u32 *rate_ptr = bpf_map_lookup_elem(&config_map, &idx);
    meta->sampling_rate = rate_ptr ? *rate_ptr : 100;
    
    // Send metadata to user space
    bpf_ringbuf_submit(meta, 0);
    
    // Update statistics
    update_statistics(STAT_PROCESSED_PACKETS, 1);
    update_statistics(STAT_PROCESSED_BYTES, packet_size);
    update_statistics(STAT_SAMPLED_PACKETS, 1);
    
    // Pass packet to kernel for normal processing
    return XDP_PASS;
}

// Periodic cleanup to remove expired flows
SEC("raw_tp/sys_enter_nanosleep")
int cleanup_flows(void *ctx) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 timeout_ns = 60 * 1000000000ULL; // 60 seconds in nanoseconds
    
    // Iterate over a limited number of flows (due to BPF loop restrictions)
    struct flow_key key, next_key;
    __builtin_memset(&key, 0, sizeof(key));
    __builtin_memset(&next_key, 0, sizeof(next_key));
    
    // Increased iteration count to process more flows per call
    // This is still bounded by BPF verifier constraints
    // but allows more flows to be cleaned up in each iteration
    #define MAX_CLEANUP_ITERATIONS 32
    
    // BPF only allows limited number of iterations, so we'll do our best
    for (int i = 0; i < MAX_CLEANUP_ITERATIONS; i++) {
        if (bpf_map_get_next_key(&flow_map, &key, &next_key) != 0) {
            break; // No more flows
        }
        
        struct flow_state *state = bpf_map_lookup_elem(&flow_map, &next_key);
        if (state && (current_time - state->last_update) > timeout_ns) {
            bpf_map_delete_elem(&flow_map, &next_key);
        }
        
        key = next_key;
    }
    
    return 0;
}

// Add additional periodic timer for more aggressive cleanup
// This helps ensure we clean up flows more frequently
SEC("raw_tp/sys_enter_futex")
int aggressive_cleanup_flows(void *ctx) {
    // We'll clean up flows on futex calls too, to increase cleanup frequency
    // without waiting for nanosleep calls which might be infrequent
    cleanup_flows(ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";
