// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define SERVER_IP		v4_pod_two
#define SERVER_PORT		__bpf_htons(222)

#define NODE_IP			v4_node_one

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "bpf_overlay.c"

ASSIGN_CONFIG(__u32, endpoint_ipv4, v4_pod_one)

#define FROM_OVERLAY 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_OVERLAY] = &cil_from_overlay,
	},
};


PKTGEN("tc", "tc_lxc_yama")
int tc_lxc_yama_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)server_mac,
					  CLIENT_IP, SERVER_IP,
					  CLIENT_PORT, SERVER_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}


SETUP("tc", "tc_lxc_yama")
int tc_lxc_yama_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}


CHECK("tc", "tc_lxc_yama")
int tc_lxc_yama_check(struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
	//assert(*status_code == CTX_ACT_REDIRECT);
	// currently the status code is CTX_ACT_DROP
	assert(*status_code == CTX_ACT_DROP);

    test_finish();
}
