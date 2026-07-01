package logger

import (
	"ai-edr/internal/analyzer"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTitleFromHistory(t *testing.T) {
	history := []analyzer.Message{
		{Role: "system", Content: "ignored"},
		{Role: "user", Content: "需求：年后"},
	}
	got := TitleFromHistory(history)
	if got != "年后安全排查报告" {
		t.Fatalf("title=%q", got)
	}
}

func TestReporterSetTitle(t *testing.T) {
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldwd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	reporter, path, err := NewReporter()
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	if err := reporter.SetTitle("查看当前系统服务"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "\xEF\xBB\xBF# 查看当前系统服务报告\n") {
		t.Fatalf("unexpected report header: %q", string(data[:80]))
	}
}
