// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

const (
	// MapNameSnat4Global represents global IPv4 NAT table.
	MapNameSnat4Global = "cilium_snat_v4_external"
	// MapNameSnat6Global represents global IPv6 NAT table.
	MapNameSnat6Global = "cilium_snat_v6_external"

	// MinPortSnatDefault represents default min port from range.
	MinPortSnatDefault = 1024
	// MaxPortSnatDefault represents default max port from range.
	MaxPortSnatDefault = 65535

	// MapNameSnat4AllocRetries represents the histogram of IPv4 NAT port allocation retries.
	MapNameSnat4AllocRetries = "cilium_snat_v4_alloc_retries"
	// MapNameSnat6AllocRetries represents the histogram of IPv6 NAT port allocation retries.
	MapNameSnat6AllocRetries = "cilium_snat_v6_alloc_retries"

	// SnatCollisionRetries represents the maximum number of port allocation retries.
	SnatCollisionRetries = 32
)

// Map represents a NAT map.
// It also implements the NatMap interface.
type Map struct {
	bpf.Map
	family IPFamily
}

// NatEntry is the interface describing values to the NAT map.
type NatEntry interface {
	bpf.MapValue

	// ToHost converts fields to host byte order.
	ToHost() NatEntry

	// Dumps the Nat entry as string.
	Dump(key NatKey, toDeltaSecs func(uint64) string) string
}

// A "Record" designates a map entry (key + value), but avoid "entry" because of
// possible confusion with "NatEntry" (actually the value part).
// This type is used for JSON dump and mock maps.
type NatMapRecord struct {
	Key   NatKey
	Value NatEntry
}

type commonMap interface {
	Open() error
	Close() error
	Path() (string, error)
}

// NatMap interface represents a NAT map, and can be reused to implement mock
// maps for unit tests.
type NatMap interface {
	commonMap
	DumpEntries() (string, error)
	DumpWithCallback(bpf.DumpCallback) error
}

type RetriesMap interface {
	commonMap
	DumpPerCPUWithCallback(bpf.DumpPerCPUCallback) error
	ClearAll() error
}

// NewMap instantiates a Map.
func NewMap(registry *metrics.Registry, name string, family IPFamily, entries int) *Map {
	var mapKey bpf.MapKey
	var mapValue bpf.MapValue

	if family == IPv4 {
		mapKey = &NatKey4{}
		mapValue = &NatEntry4{}
	} else {
		mapKey = &NatKey6{}
		mapValue = &NatEntry6{}
	}

	return &Map{
		Map: *bpf.NewMap(
			name,
			ebpf.LRUHash,
			mapKey,
			mapValue,
			entries,
			0,
		).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(name)).
			WithPressureMetric(registry),
		family: family,
	}
}

type RetriesKey struct {
	Key uint32
}

func (k *RetriesKey) String() string  { return fmt.Sprintf("%d", k.Key) }
func (k *RetriesKey) New() bpf.MapKey { return &RetriesKey{} }

type RetriesValue struct {
	Value uint32
}

type RetriesValues []RetriesValue

func (k *RetriesValue) String() string    { return fmt.Sprintf("%d", k.Value) }
func (k *RetriesValue) New() bpf.MapValue { return &RetriesValue{} }
func (k *RetriesValue) NewSlice() any     { return &RetriesValues{} }

type RetriesMapRecord struct {
	Key   *RetriesKey
	Value *RetriesValue
}

func NewRetriesMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.PerCPUArray,
		&RetriesKey{},
		&RetriesValue{},
		SnatCollisionRetries+1,
		0,
	)
}

// DumpBatch4 uses batch iteration to walk the map and applies fn for each batch of entries.
func (m *Map) DumpBatch4(fn func(*tuple.TupleKey4, *NatEntry4)) (count int, err error) {
	if m.family != IPv4 {
		return 0, fmt.Errorf("not implemented: wrong ip family: %s", m.family)
	}

	iter := bpf.NewBatchIterator[tuple.TupleKey4, NatEntry4](&m.Map)
	for key, entry := range iter.IterateAll(context.Background()) {
		count++
		fn(key, entry)
	}
	return count, nil
}

// DumpBatch6 uses batch iteration to walk the map and applies fn for each batch of entries.
func (m *Map) DumpBatch6(fn func(*tuple.TupleKey6, *NatEntry6)) (count int, err error) {
	if m.family != IPv6 {
		return 0, fmt.Errorf("not implemented: wrong ip family: %s", m.family)
	}
	iter := bpf.NewBatchIterator[tuple.TupleKey6, NatEntry6](&m.Map)
	for key, entry := range iter.IterateAll(context.Background()) {
		count++
		fn(key, entry)
	}
	return count, nil
}

func (m *Map) Delete(k bpf.MapKey) (deleted bool, err error) {
	deleted, err = (&m.Map).SilentDelete(k)
	return
}

func (m *Map) DumpStats() *bpf.DumpStats {
	return bpf.NewDumpStats(&m.Map)
}

func (m *Map) DumpReliablyWithCallback(cb bpf.DumpCallback, stats *bpf.DumpStats) error {
	return (&m.Map).DumpReliablyWithCallback(cb, stats)
}

// DumpEntriesWithTimeDiff iterates through Map m and writes the values of the
// nat entries in m to a string. If clockSource is not nil, it uses it to
// compute the time difference of each entry from now and prints that too.
func DumpEntriesWithTimeDiff(m NatMap, clockSource *models.ClockSource) (string, error) {
	var toDeltaSecs func(uint64) string
	var sb strings.Builder

	if clockSource == nil {
		toDeltaSecs = func(t uint64) string {
			return fmt.Sprintf("? (raw %d)", t)
		}
	} else {
		now, err := timestamp.GetCTCurTime(clockSource)
		if err != nil {
			return "", err
		}
		tsConverter, err := timestamp.NewCTTimeToSecConverter(clockSource)
		if err != nil {
			return "", err
		}
		tsecNow := tsConverter(now)
		toDeltaSecs = func(t uint64) string {
			tsec := tsConverter(uint64(t))
			diff := int64(tsecNow) - int64(tsec)
			return fmt.Sprintf("%dsec ago", diff)
		}
	}

	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(NatKey)
		if !key.ToHost().Dump(&sb, false) {
			return
		}
		val := v.(NatEntry)
		sb.WriteString(val.ToHost().Dump(key, toDeltaSecs))
	}
	err := m.DumpWithCallback(cb)
	return sb.String(), err
}

// DoDumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func DoDumpEntries(m NatMap) (string, error) {
	return DumpEntriesWithTimeDiff(m, nil)
}

// DumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func (m *Map) DumpEntries() (string, error) {
	return DoDumpEntries(m)
}

type gcStats struct {
	*bpf.DumpStats

	// deleted is the number of keys deleted
	deleted uint32

	// dumpError records any error that occurred during the dump.
	dumpError error
}

func statStartGc(m *Map) gcStats {
	return gcStats{
		DumpStats: bpf.NewDumpStats(&m.Map),
	}
}

func doFlush4(m *Map) gcStats {
	stats := statStartGc(m)
	filterCallback := func(key bpf.MapKey, _ bpf.MapValue) {
		err := (&m.Map).DeleteLocked(key)
		if err != nil {
			m.Logger.Error("Unable to delete NAT entry",
				logfields.Error, err,
				logfields.Key, key,
			)
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

func doFlush6(m *Map) gcStats {
	stats := statStartGc(m)
	filterCallback := func(key bpf.MapKey, _ bpf.MapValue) {
		err := (&m.Map).DeleteLocked(key)
		if err != nil {
			m.Logger.Error("Unable to delete NAT entry",
				logfields.Error, err,
				logfields.Key, key,
			)
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

// Flush deletes all NAT mappings from the given table.
func (m *Map) Flush() int {
	if m.family == IPv4 {
		return int(doFlush4(m).deleted)
	}

	return int(doFlush6(m).deleted)
}

func DeleteMapping4(m *Map, tk tuple.TupleKey) error {
	ctKey, ok := tk.(*tuple.TupleKey4Global)
	if !ok {
		return fmt.Errorf("wrong type %T for key", tk)
	}
	key := NatKey4{
		TupleKey4Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(valMap.(*NatEntry4))
		rkey := key
		rkey.SourceAddr = key.DestAddr
		rkey.SourcePort = key.DestPort
		rkey.DestAddr = val.Addr
		rkey.DestPort = val.Port
		rkey.Flags = tuple.TUPLE_F_IN

		m.SilentDelete(&key)
		m.SilentDelete(&rkey)
	}
	return nil
}

func DeleteMapping6(m *Map, tk tuple.TupleKey) error {
	ctKey, ok := tk.(*tuple.TupleKey6Global)
	if !ok {
		return fmt.Errorf("wrong type %T for key", tk)
	}
	key := NatKey6{
		TupleKey6Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(valMap.(*NatEntry6))
		rkey := key
		rkey.SourceAddr = key.DestAddr
		rkey.SourcePort = key.DestPort
		rkey.DestAddr = val.Addr
		rkey.DestPort = val.Port
		rkey.Flags = tuple.TUPLE_F_IN

		m.SilentDelete(&key)
		m.SilentDelete(&rkey)
	}
	return nil
}

// Expects ingress tuple
func DeleteSwappedMapping4(m *Map, tk tuple.TupleKey) error {
	ctKey, ok := tk.(*tuple.TupleKey4Global)
	if !ok {
		return fmt.Errorf("wrong type %T for key", tk)
	}
	key := NatKey4{TupleKey4Global: *ctKey}
	// Because of #5848, we need to reverse only ports
	port := key.SourcePort
	key.SourcePort = key.DestPort
	key.DestPort = port
	key.Flags = tuple.TUPLE_F_OUT
	m.SilentDelete(&key)

	return nil
}

// Expects ingress tuple
func DeleteSwappedMapping6(m *Map, tk tuple.TupleKey) error {
	ctKey, ok := tk.(*tuple.TupleKey6Global)
	if !ok {
		return fmt.Errorf("wrong type %T for key", tk)
	}
	key := NatKey6{TupleKey6Global: *ctKey}
	// Because of #5848, we need to reverse only ports
	port := key.SourcePort
	key.SourcePort = key.DestPort
	key.DestPort = port
	key.Flags = tuple.TUPLE_F_OUT
	m.SilentDelete(&key)

	return nil
}

// GlobalMaps returns all global NAT maps.
func GlobalMaps(registry *metrics.Registry, ipv4, ipv6, nodeport bool) (ipv4Map, ipv6Map *Map) {
	if !nodeport {
		return
	}
	if ipv4 {
		ipv4Map = NewMap(registry, MapNameSnat4Global, IPv4, maxEntries())
	}
	if ipv6 {
		ipv6Map = NewMap(registry, MapNameSnat6Global, IPv6, maxEntries())
	}
	return
}

// ClusterMaps returns all NAT maps for given clusters
func ClusterMaps(clusterID uint32, ipv4, ipv6 bool) (ipv4Map, ipv6Map *Map, err error) {
	if ipv4 {
		ipv4Map, err = GetClusterNATMap(clusterID, IPv4)
		if err != nil {
			return
		}
	}
	if ipv6 {
		ipv6Map, err = GetClusterNATMap(clusterID, IPv6)
		if err != nil {
			return
		}
	}
	return
}

func maxEntries() int {
	if option.Config.NATMapEntriesGlobal != 0 {
		return option.Config.NATMapEntriesGlobal
	}
	return option.LimitTableMax
}

// RetriesMaps returns the maps that contain the histograms of the number of retries.
func RetriesMaps(ipv4, ipv6, nodeport bool) (ipv4RetriesMap, ipv6RetriesMap RetriesMap) {
	if !nodeport {
		return
	}
	if ipv4 {
		ipv4RetriesMap = NewRetriesMap(MapNameSnat4AllocRetries)
	}
	if ipv6 {
		ipv6RetriesMap = NewRetriesMap(MapNameSnat6AllocRetries)
	}
	return
}

func CreateRetriesMaps(ipv4, ipv6 bool) error {
	if ipv4 {
		ipv4Map := NewRetriesMap(MapNameSnat4AllocRetries)
		if err := ipv4Map.OpenOrCreate(); err != nil {
			return err
		}
	}
	if ipv6 {
		ipv6Map := NewRetriesMap(MapNameSnat6AllocRetries)
		if err := ipv6Map.OpenOrCreate(); err != nil {
			return err
		}
	}
	return nil
}
