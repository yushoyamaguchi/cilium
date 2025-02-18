// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genevemac

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
)

// MapName and MaxEntries match your BPF definitions
const (
	MapName    = "cilium_geneve_mac"
	MaxEntries = 2
)

// GeneveMacKey corresponds to the `__u32` key in your BPF map
type GeneveMacKey struct {
	Key uint32
}

// GeneveMacValue corresponds to the struct geneve_mac_addr in BPF:
//
//	struct geneve_mac_addr {
//	    __u8 addr[6];
//	    __u8 pad[2];
//	};
type GeneveMacValue struct {
	Addr [6]byte
	Pad  [2]byte
}

// GeneveMacMap is a wrapper around the cilium BPF map object
type GeneveMacMap struct {
	Map *ebpf.Map
}

// NewGeneveMacMap creates and opens/pins the array map
func NewGeneveMacMap() (*GeneveMacMap, error) {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(GeneveMacKey{})),
		ValueSize:  uint32(unsafe.Sizeof(GeneveMacValue{})),
		MaxEntries: MaxEntries,
		Pinning:    ebpf.PinByName,
	})
	if err := m.OpenOrCreate(); err != nil {
		return nil, err
	}
	return &GeneveMacMap{Map: m}, nil
}
