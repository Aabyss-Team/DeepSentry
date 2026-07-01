package executor

import (
	"strings"
	"testing"
	"time"

	"ai-edr/internal/config"
)

func TestMatchTargets(t *testing.T) {
	targets := []config.TargetConfig{
		{Name: "web-01", Protocol: "ssh", Host: "10.0.0.1:22", Tags: []string{"prod", "web"}},
		{Name: "legacy-01", Protocol: "telnet", Host: "10.0.0.2:23", Tags: []string{"legacy"}},
		{Name: "ftp-01", Protocol: "ftp", Host: "10.0.0.3:21", Tags: []string{"evidence"}},
	}
	if got := MatchTargets(targets, "prod"); len(got) != 1 || got[0].Name != "web-01" {
		t.Fatalf("tag selector failed: %#v", got)
	}
	if got := MatchTargets(targets, "telnet"); len(got) != 1 || got[0].Name != "legacy-01" {
		t.Fatalf("protocol selector failed: %#v", got)
	}
	if got := MatchTargets(targets, "all"); len(got) != 3 {
		t.Fatalf("all selector failed: %#v", got)
	}
}

func TestFormatFleetResults(t *testing.T) {
	results := []FleetResult{
		{Target: config.TargetConfig{Name: "a", Protocol: "ssh", Host: "h"}, Success: true, Output: "ok", Duration: time.Millisecond},
		{Target: config.TargetConfig{Name: "b", Protocol: "ftp", Host: "f"}, Success: false, Error: "no shell", Duration: time.Millisecond},
	}
	out := FormatFleetResults(results)
	if !strings.Contains(out, "1/2 成功") || !strings.Contains(out, "[ERR] b") {
		t.Fatalf("unexpected format: %s", out)
	}
}

func TestRunFleetRejectsFTPShellExec(t *testing.T) {
	results := RunFleet([]config.TargetConfig{
		{Name: "ftp-01", Protocol: "ftp", Host: "127.0.0.1:21"},
	}, "all", "whoami", 1)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %#v", results)
	}
	if results[0].Success || !strings.Contains(results[0].Error, "FTP 目标不支持 shell 命令") {
		t.Fatalf("expected ftp shell rejection, got %#v", results[0])
	}
}
