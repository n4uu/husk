package beacon

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const nameColumnWidth = 32

// jsonSetting is the on-the-wire JSON shape for one decoded setting. Raw is
// left out, since every kind of Value already carries whatever of the raw
// bytes is worth keeping (hex, a string, a struct).
type jsonSetting struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// RenderJSON encodes settings as a JSON array, sorted by index so the output
// is stable across runs of the same input.
func RenderJSON(settings []Setting) ([]byte, error) {
	sorted := sortedByIndex(settings)
	out := make([]jsonSetting, len(sorted))
	for i, s := range sorted {
		out[i] = jsonSetting{Index: s.Index, Name: s.Name, Type: s.Type.String(), Value: s.Value}
	}
	return json.MarshalIndent(out, "", "  ")
}

// RenderText formats settings as aligned "Name - value" lines for a
// terminal. Settings in the silent set (raw stub/shellcode blobs, see
// settings.go) are skipped unless showSilent is set; an empty or
// zero-valued setting is skipped either way, since a config with 60-odd
// possible settings typically only sets a handful of them.
func RenderText(settings []Setting, showSilent bool) string {
	var b strings.Builder
	for _, s := range sortedByIndex(settings) {
		if !showSilent && silent[s.Name] {
			continue
		}

		lines := valueLines(s.Value)
		if len(lines) == 0 {
			continue
		}

		fmt.Fprintf(&b, "%-*s - %s\n", nameColumnWidth, s.Name, lines[0])
		for _, l := range lines[1:] {
			fmt.Fprintf(&b, "%-*s   %s\n", nameColumnWidth, "", l)
		}
	}
	return b.String()
}

// valueLines renders one Setting.Value as the lines RenderText should print
// for it, or nil if the value is empty/unset and should be skipped.
func valueLines(v any) []string {
	switch val := v.(type) {
	case nil:
		return nil
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case bool:
		if val {
			return []string{"True"}
		}
		return []string{"False"}
	case int64:
		return []string{fmt.Sprintf("%d", val)}
	case []string:
		if len(val) == 0 {
			return nil
		}
		return val
	case PublicKeyValue:
		if val.Hex == "" {
			return nil
		}
		return []string{fmt.Sprintf("md5:%s", val.MD5)}
	case ProcInjectTransformValue:
		if val.empty() {
			return nil
		}
		var lines []string
		if val.Prepend != "" {
			lines = append(lines, "prepend="+val.Prepend)
		}
		if val.Append != "" {
			lines = append(lines, "append="+val.Append)
		}
		return lines
	case HeaderTransformValue:
		if val.empty() {
			return nil
		}
		var lines []string
		appendCategory := func(label string, items []string) {
			for _, item := range items {
				lines = append(lines, label+": "+item)
			}
		}
		appendCategory("const-header", val.ConstHeaders)
		appendCategory("const-param", val.ConstParams)
		appendCategory("metadata", val.Metadata)
		appendCategory("session-id", val.SessionID)
		appendCategory("output", val.Output)
		return lines
	default:
		return []string{fmt.Sprintf("%v", val)}
	}
}

func sortedByIndex(settings []Setting) []Setting {
	out := make([]Setting, len(settings))
	copy(out, settings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
