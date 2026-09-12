package beacon

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderTextHidesSilentByDefault(t *testing.T) {
	settings := decodeFields(t, Short(2, 443), Raw(14, []byte("shellcode-stub-bytes")))

	text := RenderText(settings, false)
	if strings.Contains(text, "SpawnTo") {
		t.Error("RenderText(showSilent=false) should hide SpawnTo")
	}
	if !strings.Contains(text, "Port") {
		t.Error("RenderText should show non-silent settings")
	}

	all := RenderText(settings, true)
	if !strings.Contains(all, "SpawnTo") {
		t.Error("RenderText(showSilent=true) should show SpawnTo")
	}
}

func TestRenderTextSkipsEmptyValues(t *testing.T) {
	settings := decodeFields(t, Int(40, 0)) // KillDate unset -> ""
	if text := RenderText(settings, true); strings.Contains(text, "KillDate") {
		t.Errorf("RenderText should skip an unset KillDate, got %q", text)
	}
}

func TestRenderJSONIsSortedAndValid(t *testing.T) {
	settings := decodeFields(t, Short(2, 443), Int(3, 1000))
	// Reverse the input order to prove RenderJSON sorts, not just passes through.
	settings[0], settings[1] = settings[1], settings[0]

	raw, err := RenderJSON(settings)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var decoded []jsonSetting
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("output isn't valid JSON: %v", err)
	}
	if len(decoded) != 2 || decoded[0].Index != 2 || decoded[1].Index != 3 {
		t.Errorf("RenderJSON output not sorted by index: %+v", decoded)
	}
}

func TestSourcesFallsBackToWholeFileForNonPE(t *testing.T) {
	sources := Sources([]byte("not a PE file at all"))
	if len(sources) != 1 || sources[0].Name != "raw input" {
		t.Errorf("Sources(non-PE) = %+v, want a single 'raw input' source", sources)
	}
}
