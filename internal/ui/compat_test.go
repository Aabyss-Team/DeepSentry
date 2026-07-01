package ui

import (
	"os"
	"testing"
)

func TestPlainTextModeEnvOverrides(t *testing.T) {
	t.Setenv("DEEPSENTRY_PLAIN", "1")
	t.Setenv("DEEPSENTRY_FANCY", "")
	if !PlainTextMode() {
		t.Fatal("DEEPSENTRY_PLAIN should force terminal-safe output")
	}
}

func TestFancyEnvOverridesPlainTerminal(t *testing.T) {
	t.Setenv("DEEPSENTRY_PLAIN", "")
	t.Setenv("DEEPSENTRY_FANCY", "1")
	t.Setenv("TERM", "dumb")
	t.Setenv("LANG", "C")
	if PlainTextMode() {
		t.Fatal("DEEPSENTRY_FANCY should allow emoji/box drawing output")
	}
}

func TestTerminalTextReplacesAmbiguousSymbols(t *testing.T) {
	t.Setenv("DEEPSENTRY_PLAIN", "1")
	t.Setenv("DEEPSENTRY_FANCY", "")
	t.Setenv("DEEPSENTRY_NO_COLOR", "1")
	got := TerminalText("\033[31m✅ ok 🔌 api ⚠️ warn\033[0m")
	want := "[OK] ok [API] api [WARN] warn"
	if got != want {
		t.Fatalf("TerminalText()=%q want %q", got, want)
	}
}

func TestPlainTextKeepsColorByDefault(t *testing.T) {
	t.Setenv("DEEPSENTRY_PLAIN", "1")
	t.Setenv("DEEPSENTRY_NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("CLICOLOR", "1")
	oldNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	_ = os.Unsetenv("NO_COLOR")
	t.Cleanup(func() {
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", oldNoColor)
		}
	})
	got := TerminalText("\033[31m✅ ok\033[0m")
	want := "\033[31m[OK] ok\033[0m"
	if got != want {
		t.Fatalf("TerminalText()=%q want %q", got, want)
	}
}

func TestNoColorDisablesANSI(t *testing.T) {
	t.Setenv("DEEPSENTRY_NO_COLOR", "1")
	if ColorEnabled() {
		t.Fatal("DEEPSENTRY_NO_COLOR should disable colors")
	}
	got := StripANSIIfPlain("\033[32mgreen\033[0m")
	if got != "green" {
		t.Fatalf("StripANSIIfPlain()=%q", got)
	}
}
