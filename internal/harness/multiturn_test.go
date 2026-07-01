package harness

import (
	"ai-edr/internal/analyzer"
	"testing"
)

func TestCountUserTurns(t *testing.T) {
	h := []analyzer.Message{
		{Role: "user", Content: "a"},
		{Role: "assistant", Content: "b"},
		{Role: "user", Content: "c"},
	}
	if n := CountUserTurns(h); n != 2 {
		t.Fatalf("expected 2 user turns, got %d", n)
	}
}

func TestMultiTurnExtraPrompt(t *testing.T) {
	h := []analyzer.Message{{Role: "user", Content: "only one"}}
	if p := MultiTurnExtraPrompt(true, &h); p != "" {
		t.Fatal("single turn should not inject follow-up prompt")
	}
	h = append(h, analyzer.Message{Role: "user", Content: "follow up"})
	if p := MultiTurnExtraPrompt(true, &h); p == "" {
		t.Fatal("second user turn should inject follow-up prompt")
	}
}
