package main

import (
	"os"
	"testing"

	"ai-edr/internal/config"
	"ai-edr/internal/executor"

	"github.com/spf13/viper"
)

func TestSwitchToLocalModeClearsProtocolAndRemoteFields(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	oldConfig := config.GlobalConfig
	defer func() {
		config.GlobalConfig = oldConfig
		viper.Reset()
	}()
	viper.Reset()
	viper.SetConfigType("yaml")
	viper.Set("target_protocol", "ssh")
	viper.Set("ssh_host", "127.0.0.1:2222")
	viper.Set("ssh_user", "root")
	viper.Set("ssh_password", "bad")

	config.GlobalConfig = config.Config{
		TargetProtocol: "ssh",
		SSHHost:        "127.0.0.1:2222",
		SSHUser:        "root",
		SSHPassword:    "bad",
	}

	switchToLocalMode()

	if got := config.GlobalConfig.TargetProtocol; got != "local" {
		t.Fatalf("TargetProtocol = %q, want local", got)
	}
	if config.GlobalConfig.SSHHost != "" || viper.GetString("ssh_host") != "" {
		t.Fatalf("SSH host should be cleared, global=%q viper=%q", config.GlobalConfig.SSHHost, viper.GetString("ssh_host"))
	}
	if got := viper.GetString("target_protocol"); got != "local" {
		t.Fatalf("viper target_protocol = %q, want local", got)
	}
	if err := executor.Init(config.GlobalConfig); err != nil {
		t.Fatalf("executor should initialize local mode after switch, got %v", err)
	}
	if got := executor.CurrentMode(); got != "local" {
		t.Fatalf("executor mode = %q, want local", got)
	}
}
