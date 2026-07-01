package ui

import (
	"strings"
	"testing"

	"github.com/mattn/go-runewidth"
)

func TestRobotLogoLinesAligned(t *testing.T) {
	lines := RobotLogoLines()
	if len(lines) != 9 {
		t.Fatalf("expected 9 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if got := runewidth.StringWidth(line); got != robotLogoWidth {
			t.Fatalf("line %d width=%d want %d: %q", i, got, robotLogoWidth, line)
		}
	}
	if !strings.Contains(lines[5], "SENTRY") {
		t.Fatalf("missing SENTRY in body line: %q", lines[5])
	}
}

func TestLogoArtIsASCIIAndAligned(t *testing.T) {
	lines := strings.Split(strings.Trim(LogoArt, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("logo should not be empty")
	}
	want := runewidth.StringWidth(lines[0])
	for i, line := range lines {
		if got := runewidth.StringWidth(line); got != want {
			t.Fatalf("line %d width=%d want %d: %q", i, got, want, line)
		}
		for _, r := range line {
			if r > 127 {
				t.Fatalf("logo should stay ASCII for no-tui compatibility, got %q in %q", r, line)
			}
		}
	}
	if !strings.Contains(LogoArt, "S E N T R Y") {
		t.Fatalf("missing SENTRY in logo: %q", LogoArt)
	}
}
