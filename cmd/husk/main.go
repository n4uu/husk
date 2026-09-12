// Command husk locates and decodes a Cobalt Strike Beacon configuration
// block from a PE, a raw section dump, or a memory-dumped shellcode blob —
// for pulling C2 infrastructure and behavior out of an implant recovered
// during incident response.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/n4uu/husk/internal/beacon"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "parse":
		err = runParse(os.Args[2:])
	case "fixture":
		err = runFixture(os.Args[2:])
	case "-version", "--version", "version":
		fmt.Printf("husk %s\n", version)
		return
	case "-h", "-help", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "husk: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `husk — Cobalt Strike Beacon configuration extractor

usage:
  husk parse [-json] [-all] <file>       decode a Beacon config from a PE, section dump, or memory blob
  husk fixture [flags] -out <file>       generate a synthetic (non-malicious) test config, for trying husk without a real sample
  husk version

run "husk parse -h" or "husk fixture -h" for flag details.
`)
}

func runParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the decoded config as JSON instead of text")
	showAll := fs.Bool("all", false, "also print raw stub/shellcode blob settings that are normally hidden")
	fs.Parse(args)

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: husk parse [-json] [-all] <file>")
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read %s: %w", fs.Arg(0), err)
	}

	for _, src := range beacon.Sources(data) {
		cfg, ok := beacon.RecoverConfig(src.Data)
		if !ok {
			continue
		}

		fmt.Fprintf(os.Stderr, "found config in %s at offset %d, key %s (%d settings)\n\n",
			src.Name, cfg.Offset, cfg.Key, len(cfg.Settings))

		if *asJSON {
			out, err := beacon.RenderJSON(cfg.Settings)
			if err != nil {
				return fmt.Errorf("encode json: %w", err)
			}
			fmt.Println(string(out))
		} else {
			fmt.Print(beacon.RenderText(cfg.Settings, *showAll))
		}
		return nil
	}

	return fmt.Errorf("no Beacon configuration found in %s", fs.Arg(0))
}

func runFixture(args []string) error {
	fs := flag.NewFlagSet("fixture", flag.ExitOnError)
	out := fs.String("out", "", "output file path (required)")
	c2 := fs.String("c2", "cdn.assets-delivery.invalid,/api/v1/metrics", "C2Server value: \"domain,uri\"")
	ua := fs.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "UserAgent value")
	sleep := fs.Int("sleep", 60000, "SleepTime in milliseconds")
	jitter := fs.Int("jitter", 20, "Jitter percentage")
	port := fs.Int("port", 443, "Port value")
	keyHex := fs.String("key", "0x2e", "single-byte XOR key, e.g. 0x2e (Beacon 4) or 0x69 (Beacon 3)")
	rawOnly := fs.Bool("raw", false, "write only the encoded config blob, without wrapping it in a PE")
	fs.Parse(args)

	if *out == "" {
		return fmt.Errorf("usage: husk fixture -out <file> [flags]")
	}

	key, err := beacon.KeyBytes(*keyHex)
	if err != nil || len(key) != 1 {
		return fmt.Errorf("invalid -key %q: want a single byte like 0x2e", *keyHex)
	}

	fields := []beacon.Field{
		beacon.Short(1, 8), // BeaconType: HTTPS
		beacon.Short(2, uint16(*port)),
		beacon.Int(3, int32(*sleep)),
		beacon.Int(4, 1048576),
		beacon.Short(5, uint16(*jitter)),
		beacon.Short(6, 255),
		beacon.Str(8, *c2, 256),
		beacon.Str(9, *ua, 128),
		beacon.Str(10, "/submit.php", 64),
		beacon.Raw(11, beacon.MalleableStreamBlob("remove-begin:4", "base64 decode")),
		beacon.Str(15, `\\.\pipe\msagent_%x`, 128),
		beacon.Int(37, 305419896), // Watermark — an arbitrary license/build id
		beacon.Short(38, 1),       // bStageCleanup
		beacon.Int(40, 0),         // KillDate: unset
		beacon.Short(43, 4),       // bProcInject_StartRWX: false
		beacon.Short(44, 32),      // bProcInject_UseRWX: false
		beacon.Int(45, 0x1000),
		beacon.Raw(46, beacon.ProcInjectTransformBlob(nil, nil)),
		beacon.Raw(51, []byte{3, 0}), // ProcInject_Execute: CreateRemoteThread, then terminator
		beacon.Short(52, 0),          // VirtualAllocEx
		beacon.Int(71, 0),
		beacon.Int(72, 0),
		beacon.Int(73, 0),
	}

	blob := beacon.XOR(beacon.BuildBlob(fields, 4096), key)

	payload := blob
	if !*rawOnly {
		payload = beacon.BuildMinimalPE(blob)
	}

	if err := os.WriteFile(*out, payload, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}

	fmt.Fprintf(os.Stderr, "wrote synthetic fixture to %s (%d bytes, key %s)\n", *out, len(payload), *keyHex)
	fmt.Fprintf(os.Stderr, "this is NOT malware — it's a hand-built config in husk's own test format, for trying `husk parse` end to end\n")
	return nil
}
