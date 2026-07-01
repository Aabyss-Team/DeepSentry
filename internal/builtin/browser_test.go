package builtin

import (
	"strings"
	"testing"

	"ai-edr/internal/config"
)

func TestRenderedBrowserHelpersParseDOM(t *testing.T) {
	html := `<html><head><title>DeepSentry Test</title></head><body><main id="app"><form action="/login"></form><a href="/next">next</a><p>hello world</p></main></body></html>`
	if title := firstMatch(html, `(?is)<title[^>]*>(.*?)</title>`); title != "DeepSentry Test" {
		t.Fatalf("title = %q", title)
	}
	if fragment := selectRenderedFragment(html, "#app"); !strings.Contains(fragment, "/login") {
		t.Fatalf("selector did not return main fragment: %s", fragment)
	}
	var b strings.Builder
	writeLinks(&b, html)
	if !strings.Contains(b.String(), "/next") {
		t.Fatalf("links missing: %s", b.String())
	}
	if text := renderedText(html, 100); !strings.Contains(text, "hello world") {
		t.Fatalf("text missing: %s", text)
	}
}

func TestBrowserTimeoutDefaultDoesNotRequireConfigInit(t *testing.T) {
	old := config.GlobalConfig.BrowserTimeoutSec
	config.GlobalConfig.BrowserTimeoutSec = 0
	defer func() { config.GlobalConfig.BrowserTimeoutSec = old }()
	if got := browserTimeout().Seconds(); got != 20 {
		t.Fatalf("timeout = %.0f, want 20", got)
	}
}

func TestNormalizeBrowserMode(t *testing.T) {
	tests := map[string]string{
		"":           "snapshot",
		"SNAPSHOT":   "snapshot",
		"text":       "text",
		" forms ":    "forms",
		"links":      "links",
		"screenshot": "screenshot",
		"unknown":    "snapshot",
	}
	for in, want := range tests {
		if got := normalizeBrowserMode(in); got != want {
			t.Fatalf("normalizeBrowserMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLimitedStringBufferTruncates(t *testing.T) {
	var b limitedStringBuffer
	b.max = 5
	n, err := b.Write([]byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello world") {
		t.Fatalf("Write returned %d, want %d", n, len("hello world"))
	}
	if got := b.String(); got != "hello" {
		t.Fatalf("buffer = %q, want hello", got)
	}
	if !b.truncated {
		t.Fatal("expected truncated flag")
	}
}
