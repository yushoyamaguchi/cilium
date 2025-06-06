// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getCiliumHostIPsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	allIPsCorrect := filepath.Join(tmpDir, "node_config.h")
	f, err := os.Create(allIPsCorrect)
	defer func(f *os.File) {
		require.NoError(t, f.Close())
	}(f)
	require.NoError(t, err)
	fmt.Fprintf(f, `/*
 cilium.v6.external.str fd01::b
 cilium.v6.internal.str f00d::a00:0:0:a4ad
 cilium.v6.nodeport.str []

 cilium.v4.external.str 192.168.60.11
 cilium.v4.internal.str 10.0.0.2
 cilium.v4.nodeport.str []

 cilium.v6.internal.raw 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
 cilium.v4.internal.raw 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x0, 0x2
 */

#define ENABLE_IPV4 1
#define IPV4_GATEWAY 0x100000a
#define IPV4_MASK 0xffff
#define HOST_IP 0xfd, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb
#define HOST_ID 1
#define WORLD_ID 2
#define CILIUM_LB_MAP_MAX_ENTRIES 65536
#define ENDPOINTS_MAP_SIZE 65535
#define LPM_MAP_SIZE 16384
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define POLICY_PROG_MAP_SIZE 65535
#define TRACE_PAYLOAD_LEN 128ULL
#ifndef CILIUM_NET_MAC
#define CILIUM_NET_MAC { .addr = {0x26,0x11,0x70,0xcc,0xca,0x0c}}
#endif /* CILIUM_NET_MAC */
#define CILIUM_NET_IFINDEX 356
#define CILIUM_HOST_MAC { .addr = {0x3e,0x28,0xb4,0x4b,0x95,0x25}}
#define ENCAP_IFINDEX 358
`)

	type args struct {
		nodeConfig string
	}
	tests := []struct {
		name            string
		args            args
		wantIpv4GW      net.IP
		wantIpv6Router  net.IP
		wantIpv6Address net.IP
	}{
		{
			name: "every-ip-correct",
			args: args{
				nodeConfig: allIPsCorrect,
			},
			wantIpv4GW:      net.ParseIP("10.0.0.2"),
			wantIpv6Router:  net.ParseIP("f00d::a00:0:0:a4ad"),
			wantIpv6Address: net.ParseIP("fd01::b"),
		},
		{
			name: "file-not-present",
			args: args{
				nodeConfig: "",
			},
			wantIpv4GW:     nil,
			wantIpv6Router: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIpv4GW, gotIpv6Router := getCiliumHostIPsFromFile(tt.args.nodeConfig)
			require.Equal(t, tt.wantIpv4GW, gotIpv4GW)
			require.Equal(t, tt.wantIpv6Router, gotIpv6Router)
		})
	}
}
