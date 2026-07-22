package builtin

import (
	"ai-edr/internal/config"
	"strings"
	"testing"
)

func TestFleetInventoryExplainsEvidenceNextStep(t *testing.T) {
	original := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = original })
	config.GlobalConfig.Targets = []config.TargetConfig{{Name: "sw-01", Protocol: "ssh", Host: "192.0.2.10", User: "ops", Tags: []string{"prod"}}}
	output, err := FleetInventory(Runtime{}, "all")
	if err != nil || !strings.Contains(output, "sw-01") || !strings.Contains(output, "尚未采集") || !strings.Contains(output, "fleet_exec") {
		t.Fatalf("output=%q err=%v", output, err)
	}
}
