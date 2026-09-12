package beacon

// kind selects how a raw entry's bytes are turned into a Setting.Value,
// beyond the plain int/string rendering its wire Type already implies.
type kind int

const (
	kindPlain kind = iota // int64 (short/int) or trimmed string (str)
	kindBool
	kindIPv4            // big-endian uint32 -> dotted string
	kindKillDate        // YYYYMMDD integer -> "YYYY-MM-DD" ("" if 0)
	kindHex             // opaque blob -> lowercase hex string
	kindEnum            // int64 -> name, via table or enumFn
	kindMask            // int64 -> []string of set bit names (BeaconType)
	kindPublicKey       // index 7 -> PublicKeyValue{Hex, MD5}
	kindProcInject      // indices 46/47 -> ProcInjectTransformValue
	kindMalleableStream // index 11 -> []string
	kindHeaderTransform // indices 12/13 -> HeaderTransformValue
	kindExecuteChain    // index 51 -> []string
)

// def is one catalog entry: everything needed to turn a raw Entry into a
// human-meaningful Setting.
type def struct {
	name       string
	kind       kind
	enum       map[int64]string
	enumFn     func(int64) string
	falseValue int64 // for kindBool: the integer that means "false"
}

// catalog maps a Beacon setting index to its decode rule. Indices, names and
// wire types are the format itself — every Beacon build agrees on them —
// and were verified against the public reference implementation line by
// line (README.md has citations). Indices missing from this map still
// decode fine as an untyped "unknown_N" setting; the catalog only adds the
// human label and any special rendering.
//
// Index 54 is a genuine overload in the wire format itself, not a mistake
// here: HostHeader (HTTP/HTTPS beacons) and SSH_Banner (the SSH-listener
// beacon variant) share position 54, since a given build only ever uses one
// beacon transport and so only one of the two meanings applies. husk labels
// it by the far more common HTTP case; see decode.go's doc comment for how
// this is surfaced.
var catalog = map[int]def{
	1:  {name: "BeaconType", kind: kindMask},
	2:  {name: "Port"},
	3:  {name: "SleepTime"},
	4:  {name: "MaxGetSize"},
	5:  {name: "Jitter"},
	6:  {name: "MaxDNS"},
	7:  {name: "PublicKey", kind: kindPublicKey},
	8:  {name: "C2Server"},
	9:  {name: "UserAgent"},
	10: {name: "HttpPostUri"},
	11: {name: "Malleable_C2_Instructions", kind: kindMalleableStream},
	12: {name: "HttpGet_Metadata", kind: kindHeaderTransform},
	13: {name: "HttpPost_Metadata", kind: kindHeaderTransform},
	14: {name: "SpawnTo", kind: kindHex},
	15: {name: "PipeName"},
	// 16-18 are deprecated as of Beacon 3.4 and carry no known meaning.
	19: {name: "DNS_Idle", kind: kindIPv4},
	20: {name: "DNS_Sleep"},
	21: {name: "SSH_Host"},
	22: {name: "SSH_Port"},
	23: {name: "SSH_Username"},
	24: {name: "SSH_Password_Plaintext"},
	25: {name: "SSH_Password_Pubkey", kind: kindHex},
	26: {name: "HttpGet_Verb"},
	27: {name: "HttpPost_Verb"},
	28: {name: "HttpPostChunk"},
	29: {name: "Spawnto_x86"},
	30: {name: "Spawnto_x64"},
	31: {name: "CryptoScheme"},
	32: {name: "Proxy_Config"},
	33: {name: "Proxy_User"},
	34: {name: "Proxy_Password"},
	35: {name: "Proxy_Behavior", kind: kindEnum, enum: accessType},
	36: {name: "Watermark_Hash"},
	37: {name: "Watermark"},
	38: {name: "bStageCleanup", kind: kindBool},
	39: {name: "bCFGCaution", kind: kindBool},
	40: {name: "KillDate", kind: kindKillDate},
	// 41-42 are internal build bookkeeping (sleep-mask text section bounds,
	// section-obfuscation ranges) with no stable cross-version layout.
	43: {name: "bProcInject_StartRWX", kind: kindBool, falseValue: 4},
	44: {name: "bProcInject_UseRWX", kind: kindBool, falseValue: 32},
	45: {name: "bProcInject_MinAllocSize"},
	46: {name: "ProcInject_PrependAppend_x86", kind: kindProcInject},
	47: {name: "ProcInject_PrependAppend_x64", kind: kindProcInject},
	50: {name: "bUsesCookies", kind: kindBool},
	51: {name: "ProcInject_Execute", kind: kindExecuteChain},
	52: {name: "ProcInject_AllocationMethod", kind: kindEnum, enum: allocationFunction},
	53: {name: "ProcInject_Stub", kind: kindHex},
	54: {name: "HostHeader"}, // see catalog doc comment: aliases SSH_Banner
	57: {name: "smbFrameHeader", kind: kindHex},
	58: {name: "tcpFrameHeader", kind: kindHex},
	59: {name: "headersToRemove"},
	60: {name: "DNS_Beaconing"},
	61: {name: "DNS_get_TypeA"},
	62: {name: "DNS_get_TypeAAAA"},
	63: {name: "DNS_get_TypeTXT"},
	64: {name: "DNS_put_metadata"},
	65: {name: "DNS_put_output"},
	66: {name: "DNS_resolver"},
	67: {name: "DNS_strategy", kind: kindEnum, enumFn: rotateStrategyName},
	68: {name: "DNS_strategy_rotate_seconds"},
	69: {name: "DNS_strategy_fail_x"},
	70: {name: "DNS_strategy_fail_seconds"},
	71: {name: "Retry_Max_Attempts"},
	72: {name: "Retry_Increase_Attempts"},
	73: {name: "Retry_Duration"},
}

// silent lists settings that are catalogued but rarely useful in a first
// read of a config — raw stub/shellcode blobs mostly — so the default
// human-readable report omits them. -all on the CLI shows everything.
var silent = map[string]bool{
	"PublicKey":       true,
	"ProcInject_Stub": true,
	"smbFrameHeader":  true,
	"tcpFrameHeader":  true,
	"SpawnTo":         true,
}
