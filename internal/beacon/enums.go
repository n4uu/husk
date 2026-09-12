package beacon

import "strconv"

// The tables below are fixed by the Beacon binary format itself. Every
// build agrees on them, since they're read by Beacon's own C code rather
// than chosen per-deployment. Verified against the public reference
// implementation; see README.md for citations.

// beaconType is a bitmask, not a plain enum: the reference implementation
// stores it as a mask table and tests each bit independently (`k & value`),
// with a special case for the k==0 "HTTP" bit. In every real build exactly
// one bit ends up set, but decoding it as the bitmask it actually is means
// husk renders correctly even if that ever changes.
var beaconType = []struct {
	bit  int64
	name string
}{
	{0x0, "HTTP"},
	{0x1, "Hybrid HTTP/DNS"},
	{0x2, "SMB"},
	{0x4, "TCP"},
	{0x8, "HTTPS"},
	{0x10, "Bind TCP"},
}

func beaconTypeFlags(v int64) []string {
	var flags []string
	for _, e := range beaconType {
		if e.bit == 0 && v == 0 {
			flags = append(flags, e.name)
			continue
		}
		if e.bit != 0 && v&e.bit != 0 {
			flags = append(flags, e.name)
		}
	}
	if len(flags) == 0 {
		flags = []string{unknownEnum(v)}
	}
	return flags
}

var accessType = map[int64]string{
	0x0: "use proxy server (manual)",
	0x1: "direct connection",
	0x2: "use IE proxy settings",
	0x4: "use proxy server (credentials)",
}

// executeType is the process-injection technique chain vocabulary used by
// both ProcInject_Execute (a sequence of these) and, historically, single
// injection-method settings.
var executeType = map[int64]string{
	0x1: "CreateThread",
	0x2: "SetThreadContext",
	0x3: "CreateRemoteThread",
	0x4: "RtlCreateUserThread",
	0x5: "NtQueueApcThread",
	0x8: "NtQueueApcThread-s",
}

var allocationFunction = map[int64]string{
	0: "VirtualAllocEx",
	1: "NtMapViewOfSection",
}

var rotateStrategy = []string{
	"round-robin", "random",
	"failover", "failover-5x", "failover-50x", "failover-100x",
	"failover-1m", "failover-5m", "failover-15m", "failover-30m",
	"failover-1h", "failover-3h", "failover-6h", "failover-12h", "failover-1d",
	"rotate-1m", "rotate-5m", "rotate-15m", "rotate-30m",
	"rotate-1h", "rotate-3h", "rotate-6h", "rotate-12h", "rotate-1d",
}

func rotateStrategyName(v int64) string {
	if v >= 0 && int(v) < len(rotateStrategy) {
		return rotateStrategy[v]
	}
	return unknownEnum(v)
}

func enumLookup(table map[int64]string, v int64) string {
	if name, ok := table[v]; ok {
		return name
	}
	return unknownEnum(v)
}

func unknownEnum(v int64) string {
	return "unknown(" + strconv.FormatInt(v, 10) + ")"
}
