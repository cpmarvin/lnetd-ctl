// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "jhash.h"

#define MAX_SERVERS 512
/* 0x3FFF mask to check for fragment offset field */

#define IP_FRAGMENTED 65343

#define MPLS_LS_LABEL_MASK 0xFFFFF000
#define MPLS_LS_LABEL_SHIFT 12
#define MPLS_LS_TC_MASK 0x00000E00
#define MPLS_LS_TC_SHIFT 9
#define MPLS_LS_S_MASK 0x00000100
#define MPLS_LS_S_SHIFT 8
#define MPLS_LS_TTL_MASK 0x000000FF
#define MPLS_LS_TTL_SHIFT 0

#define MPLS_STATIC_LABEL 1000000

//LPM

struct trie_value
{
	__u32 lbl;
};

struct key_4
{
	__u32 prefixlen;
	__u32 ipv4_addr;
};

/* Map for trie implementation

key: 32-bit prefix length + 32-bit routing prefix 24 + 192.168.1.0

value:  32-bit prefix + 
	routing outbound interface MAC address + 
	32-bit routing outbound interface id + 
	32-bit cost value + 
	32-bit next hop IP address:

*/

struct mpls_hdr
{
	unsigned int entry;
};

static inline struct mpls_hdr mpls_encode(unsigned int label, unsigned int ttl,
										  unsigned int tc, bool bos)
{
	struct mpls_hdr result;
	result.entry =
		//we need to convert from CPU endian to network endian
		bpf_htonl((label << MPLS_LS_LABEL_SHIFT) |
				  (tc << MPLS_LS_TC_SHIFT) |
				  (bos ? (1 << MPLS_LS_S_SHIFT) : 0) |
				  (ttl << MPLS_LS_TTL_SHIFT));
	return result;
}

struct pkt_meta
{
	__be32 src;
	__be32 dst;
	union
	{
		__u32 ports;
		__u16 port16[2];
	};
};

struct dest_info
{

	__u64 pkts;
	__u64 bytes;
	__u32 lbl;
};

struct bpf_map_def SEC("maps") priority_clients = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 50,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") priority_dst = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 50,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") default_dst = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 50,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") servers1 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32), //ipv4_address
	.value_size = sizeof(struct dest_info),
	.max_entries = MAX_SERVERS,
};

/* not used , but in the future
static __always_inline struct dest_info *hash_get_dest(struct pkt_meta *pkt)
{
	__u32 key;
	struct dest_info *tnl;

	key = jhash_2words(pkt->src, pkt->ports, MAX_SERVERS) % MAX_SERVERS;

	tnl = bpf_map_lookup_elem(&servers, &key);
	if (!tnl)
	{
		key = 0;
		tnl = bpf_map_lookup_elem(&servers, &key);
	}
	return tnl;
}
*/

/* not used
static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
									  struct pkt_meta *pkt)
{
	struct udphdr *udp;

	udp = data + off;
	if (udp + 1 > data_end)
		return false;

	pkt->port16[0] = udp->source;
	pkt->port16[1] = udp->dest;

	return true;
}


static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
									  struct pkt_meta *pkt)
{
	struct tcphdr *tcp;

	tcp = data + off;
	if (tcp + 1 > data_end)
		return false;

	pkt->port16[0] = tcp->source;
	pkt->port16[1] = tcp->dest;

	return true;
}
*/
struct packet
{
	unsigned char dmac[ETH_ALEN];
	unsigned char smac[ETH_ALEN];
	__be32 daddr;
	__be32 saddr;
};

// set new ethhdr and swap source and dest mac
static __always_inline void set_ethhdr(struct ethhdr *new_eth,
									   const struct ethhdr *old_eth,
									   __be16 h_proto)
{
	__u8 h_tmp_src[ETH_ALEN];
	__u8 h_tmp_dst[ETH_ALEN];

	__builtin_memcpy(h_tmp_src, old_eth->h_source, ETH_ALEN);
	__builtin_memcpy(h_tmp_dst, old_eth->h_dest, ETH_ALEN);

	__builtin_memcpy(new_eth->h_dest, h_tmp_src, ETH_ALEN);
	__builtin_memcpy(new_eth->h_source, h_tmp_dst, ETH_ALEN);
	new_eth->h_proto = h_proto;
}

// set new ethhdr , keep src and dst mac
static __always_inline void set_ethhdr_same(struct ethhdr *new_eth,
											const struct ethhdr *old_eth,
											__be16 h_proto)
{
	__u8 h_tmp_src[ETH_ALEN];
	__u8 h_tmp_dst[ETH_ALEN];

	__builtin_memcpy(h_tmp_src, old_eth->h_source, ETH_ALEN);
	__builtin_memcpy(h_tmp_dst, old_eth->h_dest, ETH_ALEN);

	__builtin_memcpy(new_eth->h_dest, h_tmp_dst, ETH_ALEN);
	__builtin_memcpy(new_eth->h_source, h_tmp_src, ETH_ALEN);
	new_eth->h_proto = h_proto;
}

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct pkt_meta pkt = {};

	struct ethhdr *original_header;
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;

	struct key_4 key4_dst;
	struct key_4 key4_src;

	struct trie_value *tnl;
	struct trie_value *trie_src_result;
	struct trie_value *trie_dst_result;

	struct iphdr *iph;
	struct mpls_hdr *mpls;

	__u16 pkt_size;
	__u16 payload_len;
	__u8 protocol;
	__u8 ttl;

	u32 mpls_lbl = MPLS_STATIC_LABEL;

	original_header = data;
	iph = data + off;

	if (iph + 1 > data_end)
		return XDP_DROP;
	if (iph->ihl != 5)
		return XDP_DROP;

	protocol = iph->protocol;
	payload_len = bpf_ntohs(iph->tot_len);
	ttl = iph->ttl;
	off += sizeof(struct iphdr);

	/* keep ip src and dest for later */
	pkt.src = iph->saddr;
	pkt.dst = iph->daddr;

	/* extend the packet for mpls header encapsulation */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct mpls_hdr)))
		return XDP_DROP;

	/* new data and data_end value as required by spec*/
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* relocate ethernet header to start of packet */
	new_eth = data;
	old_eth = data + (int)sizeof(struct mpls_hdr);

	if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end)
		return XDP_DROP;

	/* set ethr header and swap mac addresses */
	set_ethhdr(new_eth, old_eth, bpf_htons(ETH_P_MPLS_UC));

	/* create key with ip pkt src */
	key4_src.prefixlen = 32;
	key4_src.ipv4_addr = pkt.src;

	/* create key with ip pkt dst */
	key4_dst.prefixlen = 32;
	key4_dst.ipv4_addr = pkt.dst;

	// find ip_src in priority_clients map
	trie_src_result = bpf_map_lookup_elem(&priority_clients, &key4_src);

	if (trie_src_result)
	{
		//find the destination in priority_destinations map
		trie_dst_result = bpf_map_lookup_elem(&priority_dst, &key4_dst);

		if (trie_dst_result)
		{
			//get the label from the map for this destination
			mpls_lbl = bpf_ntohl(trie_dst_result->lbl);
			//update stats for later
			//pkt_size = (__u16)(data_end - data);
			//__sync_fetch_and_add(&tnl->pkts, 1);
			//__sync_fetch_and_add(&tnl->bytes, pkt_size);
		}
		else
		{
			//find the destination in priority_destinations map
			trie_dst_result = bpf_map_lookup_elem(&default_dst, &key4_dst);
			if (trie_dst_result)
			{
				//get the label from the map for this destination
				mpls_lbl = bpf_ntohl(trie_dst_result->lbl);
			}
		}
	}
	else
	{
		//find the destination in priority_destinations map
		trie_dst_result = bpf_map_lookup_elem(&default_dst, &key4_dst);
		if (trie_dst_result)
		{
			//get the label from the map for this destination
			mpls_lbl = bpf_ntohl(trie_dst_result->lbl);
		}
	}

	//create mpls header
	struct mpls_hdr mpls_new = mpls_encode(mpls_lbl, ttl, 0, 1);
	//allocate the correct space in the packet
	mpls = data + sizeof(*new_eth);
	//write the header
	*mpls = mpls_new;

	return XDP_TX;
}

SEC("xdp")
int loadbal(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u32 eth_proto;
	__u32 nh_off;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		return XDP_DROP;
	eth_proto = eth->h_proto;

	/* demo program only accepts ipv4 packets */
	if (eth_proto == bpf_htons(ETH_P_IP))
		return process_packet(ctx, nh_off);
	else
		return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
