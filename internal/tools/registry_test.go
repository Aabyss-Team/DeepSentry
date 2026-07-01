package tools

import (
	"strings"
	"testing"
)

func TestGetUnknownTool(t *testing.T) {
	_, _, err := Run("nonexistent", nil, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFormatCatalog(t *testing.T) {
	prompt := FormatCatalogPrompt()
	if !strings.Contains(prompt, "tool_catalog") || !strings.Contains(prompt, "按需发现") {
		t.Fatal("catalog prompt should expose discovery entry")
	}
	if strings.Contains(prompt, "host(必填), count") {
		t.Fatal("catalog prompt should not dump full tool args every turn")
	}
}

func TestRegistryCount(t *testing.T) {
	if CountEnabled() < 43 {
		t.Fatalf("expected at least 43 enabled tools, got %d", CountEnabled())
	}
}

func TestFormatCatalogDetail(t *testing.T) {
	detail := FormatCatalogDetail("网络连通", "ping")
	if !strings.Contains(detail, "ping") || !strings.Contains(detail, "host(必填)") {
		t.Fatal("catalog detail should include matching tool args")
	}
	db := FormatCatalogDetail("数据库探测", "redis")
	if !strings.Contains(db, "redis_probe") {
		t.Fatal("catalog detail should include redis_probe")
	}
	web := FormatCatalogDetail("Web探测", "snapshot")
	if !strings.Contains(web, "web_snapshot") {
		t.Fatal("catalog detail should include web_snapshot")
	}
	headless := FormatCatalogDetail("Web探测", "headless")
	if !strings.Contains(headless, "headless_browser") {
		t.Fatal("catalog detail should include headless_browser")
	}
	pcap := FormatCatalogDetail("抓包分析", "pcap")
	if !strings.Contains(pcap, "pcap_analyze") || !strings.Contains(pcap, "gopacket") {
		t.Fatal("catalog detail should include pcap_analyze")
	}
	script := FormatCatalogDetail("脚本执行", "script")
	if !strings.Contains(script, "script_run") || !strings.Contains(script, "高风险") && !strings.Contains(script, "🔴") {
		t.Fatal("catalog detail should include high-risk script_run")
	}
	transfer := FormatCatalogDetail("文件传输", "archive")
	if !strings.Contains(transfer, "archive_pack") || !strings.Contains(transfer, "archive_extract") {
		t.Fatal("catalog detail should include archive tools")
	}
	proxy := FormatCatalogDetail("代理转发", "")
	if !strings.Contains(proxy, "tcp_forward") || !strings.Contains(proxy, "socks5_proxy") {
		t.Fatal("catalog detail should include proxy forwarding tools")
	}
	fleet := FormatCatalogDetail("批量运维", "fleet")
	if !strings.Contains(fleet, "fleet_exec") || !strings.Contains(fleet, "fleet_inventory") {
		t.Fatal("catalog detail should include fleet tools")
	}
	competition := FormatCatalogDetail("比赛辅助", "")
	if !strings.Contains(competition, "flag_scan") || !strings.Contains(competition, "awd_service_check") {
		t.Fatal("catalog detail should include competition tools")
	}
	doc := FormatCatalogDetail("文档解析", "")
	if !strings.Contains(doc, "document_parse") || !strings.Contains(doc, "PDF") {
		t.Fatal("catalog detail should include document_parse")
	}
}

func TestConfigureEnabled(t *testing.T) {
	ConfigureEnabled(nil, nil)
	defer ConfigureEnabled(nil, nil)

	ConfigureEnabled([]string{"ping"}, nil)
	if _, ok := Get("ping"); !ok {
		t.Fatal("ping should be enabled")
	}
	if _, ok := Get("nmap_scan"); ok {
		t.Fatal("nmap_scan should be disabled by whitelist")
	}

	ConfigureEnabled(nil, []string{"ping"})
	if _, ok := Get("ping"); ok {
		t.Fatal("ping should be disabled by blacklist")
	}
}
