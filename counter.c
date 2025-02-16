//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TC (Traffic Control) action values
#define TC_ACT_OK 0

// Ethernet protocol numbers
#define ETH_P_IP 0x0800 // Internet Protocol packet

// Packet key structure
struct packet_key {
    __u32 src_ip;
    __u8 protocol;
    __u8 pad[3];  // Add padding to align to 32 bits
} __attribute__((packed));

// Packet information structure
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8 protocol;
    __u8 tcp_flags;
    __u64 count;
    __u64 timestamp;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct packet_key);
    __type(value, struct packet_info);
} pkt_count SEC(".maps");

SEC("tc")
int count_packets(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if we have a complete Ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Check if we have a complete IPv4 header
    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return TC_ACT_OK;

    // For egress traffic, create a composite key with IP and protocol
    struct packet_key key = {
        .src_ip = bpf_ntohl(iph->saddr),
        .protocol = iph->protocol
    };
    
    // Debug: Print source and destination IPs
    bpf_printk("Packet: src=%x dst=%x proto=%d", 
               iph->saddr, iph->daddr, iph->protocol);
    
    struct packet_info new_info = {0};
    struct packet_info *info = bpf_map_lookup_elem(&pkt_count, &key);
    
    if (info) {
        // Copy existing info
        __builtin_memcpy(&new_info, info, sizeof(new_info));
        new_info.count++;
    } else {
        // Initialize new entry
        new_info.count = 1;
    }
    
    // Update packet info
    new_info.src_ip = bpf_ntohl(iph->saddr);  // This is our node's IP
    new_info.dst_ip = bpf_ntohl(iph->daddr);
    new_info.protocol = iph->protocol;
    new_info.pkt_len = bpf_ntohs(skb->len);
    new_info.timestamp = bpf_ktime_get_ns();
    
    // Try to get port information for TCP/UDP
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void*)(iph + 1);
        if ((void*)(tcph + 1) <= data_end) {
            new_info.src_port = bpf_ntohs(tcph->source);
            new_info.dst_port = bpf_ntohs(tcph->dest);
            new_info.tcp_flags = (tcph->fin) | 
                               (tcph->syn << 1) | 
                               (tcph->rst << 2) | 
                               (tcph->psh << 3) |
                               (tcph->ack << 4) | 
                               (tcph->urg << 5);
            bpf_printk("TCP packet: %d -> %d flags=%x", 
                      new_info.src_port, new_info.dst_port, new_info.tcp_flags);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void*)(iph + 1);
        if ((void*)(udph + 1) <= data_end) {
            new_info.src_port = bpf_ntohs(udph->source);
            new_info.dst_port = bpf_ntohs(udph->dest);
            bpf_printk("UDP packet: src_port=%d dst_port=%d len=%d", 
                      new_info.src_port, new_info.dst_port, new_info.pkt_len);
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void*)(iph + 1);
        if ((void*)(icmph + 1) <= data_end) {
            new_info.src_port = icmph->type;   
            new_info.dst_port = icmph->code;   
            bpf_printk("ICMP packet: type=%d code=%d len=%d",
                      icmph->type, icmph->code, new_info.pkt_len);
        }
    }
    
    // Add debug information
    bpf_printk("Packet protocol: %d, length: %d", iph->protocol, new_info.pkt_len);
    
    // Add debug information before map update
    bpf_printk("Updating map - proto=%d src_ip=%x dst_ip=%x src_port=%d dst_port=%d count=%d", 
               new_info.protocol, new_info.src_ip, new_info.dst_ip, 
               new_info.src_port, new_info.dst_port, new_info.count);
    
    bpf_map_update_elem(&pkt_count, &key, &new_info, BPF_ANY);
    
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";