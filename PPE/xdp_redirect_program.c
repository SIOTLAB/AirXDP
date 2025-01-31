/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "xdp_metadata.h"

#define MAX_SOCKS 1

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

static unsigned int index;

static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
	__u64 u = 0;
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--)
		u = u << 8 | addr[i];
	return u;
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	struct xdp_meta *meta= {0};
	bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));

    	index = ctx->rx_queue_index;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *data_meta = (void *)(long)ctx->data_meta;

	meta = data_meta;

	if (meta + 1 > data) {
		return XDP_PASS;
	}

	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);

	if ((void *)eth + offset > data_end)
	 	return 0;

	struct iphdr *ip = data + sizeof(struct ethhdr);
	if(ip + 1 > data_end)
		return 0;
	
	int ip_proto;

	ip_proto = ip->protocol;

	meta->rx_timestamp = bpf_ktime_get_ns();

    if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP){
		if(ctx->ingress_ifindex == 6 && ether_addr_to_u64(eth->h_source) == 19367955466208){
			if (bpf_map_lookup_elem(&xsks_map, &index)){
				return bpf_redirect_map(&xsks_map, index, 0);
			}
		}
		else if(ctx->ingress_ifindex == 3 && ether_addr_to_u64(eth->h_source) == 51255047864328){
			if (bpf_map_lookup_elem(&xsks_map, &index)){
				return bpf_redirect_map(&xsks_map, index, 0);
			}
		}
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
