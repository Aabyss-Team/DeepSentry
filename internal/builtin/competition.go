package builtin

import (
	"ai-edr/internal/config"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

var defaultFlagPattern = regexp.MustCompile(`(?i)(flag|ctf|awd)\{[^}\s]{4,120}\}|[a-f0-9]{32}`)

const (
	maxFlagScanRead    = 2 << 20
	maxFlagScanVisited = 3000
	maxAWDCheckTargets = 100
)

type flagScanState struct {
	hits      []string
	visited   int
	truncated bool
}

func FlagScan(rt Runtime, root, pattern string, limit int) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	if limit <= 0 {
		limit = 80
	}
	if limit > 500 {
		limit = 500
	}
	re := defaultFlagPattern
	if strings.TrimSpace(pattern) != "" {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return "", fmt.Errorf("pattern 非法: %w", err)
		}
		re = compiled
	}

	state := &flagScanState{}
	scanPath(root, re, limit, 0, state)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s CTF/AWD Flag Scan\nRoot: %s\nLimit: %d\n\n", rt.tag(), root, limit))
	if len(state.hits) == 0 {
		b.WriteString("(未发现匹配项)\n")
		if state.truncated {
			b.WriteString("\n...(扫描已达到资源上限，结果可能不完整)...\n")
		}
		return b.String(), nil
	}
	for _, h := range state.hits {
		b.WriteString("- " + h + "\n")
	}
	if state.truncated {
		b.WriteString("\n...(扫描已达到资源上限，结果可能不完整)...\n")
	}
	return b.String(), nil
}

func scanPath(path string, re *regexp.Regexp, limit, depth int, state *flagScanState) {
	if len(state.hits) >= limit || depth > 4 || state.visited >= maxFlagScanVisited {
		if state.visited >= maxFlagScanVisited {
			state.truncated = true
		}
		return
	}
	state.visited++
	data, err := readTargetLimited(path, maxFlagScanRead)
	if err == nil && looksText(data) {
		for _, m := range re.FindAllString(string(data), 20) {
			state.hits = append(state.hits, fmt.Sprintf("%s: %s", path, truncateOneLine(m, 180)))
			if len(state.hits) >= limit {
				return
			}
		}
		return
	}
	entries, err := listTarget(path)
	if err != nil {
		return
	}
	sort.Strings(entries)
	for _, name := range entries {
		if len(state.hits) >= limit || state.visited >= maxFlagScanVisited {
			if state.visited >= maxFlagScanVisited {
				state.truncated = true
			}
			return
		}
		if shouldSkipFlagScanName(name) {
			continue
		}
		scanPath(joinTargetPath(path, name), re, limit, depth+1, state)
	}
}

func shouldSkipFlagScanName(name string) bool {
	lower := strings.ToLower(strings.Trim(strings.TrimSpace(name), "/"))
	skips := map[string]bool{
		"proc":         true,
		"sys":          true,
		"dev":          true,
		".git":         true,
		".svn":         true,
		"node_modules": true,
		"__pycache__":  true,
		"vendor":       true,
		".ds_store":    true,
	}
	return skips[lower]
}

func joinTargetPath(base, name string) string {
	base = strings.TrimRight(base, "/")
	if base == "" || base == "." {
		return name
	}
	return base + "/" + name
}

func AWDServiceCheck(rt Runtime, targets string, timeoutSec int) (string, error) {
	items := splitTargets(targets)
	if len(items) == 0 {
		return "", fmt.Errorf("targets 不能为空，支持逗号分隔 URL 或 host:port")
	}
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	if timeoutSec > 15 {
		timeoutSec = 15
	}
	truncated := false
	if len(items) > maxAWDCheckTargets {
		items = items[:maxAWDCheckTargets]
		truncated = true
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s AWD Service Check\nTimeout: %ds\n\n", rt.tag(), timeoutSec))
	for _, item := range items {
		status := checkService(item, time.Duration(timeoutSec)*time.Second)
		b.WriteString(fmt.Sprintf("- %s  %s\n", item, status))
	}
	if truncated {
		b.WriteString(fmt.Sprintf("\n...(targets 超过 %d，仅检查前 %d 个)...\n", maxAWDCheckTargets, maxAWDCheckTargets))
	}
	return b.String(), nil
}

func splitTargets(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func checkService(target string, timeout time.Duration) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return "ERR " + err.Error()
		}
		resp, err := config.HTTPClient(timeout).Do(req)
		if err != nil {
			return "DOWN " + err.Error()
		}
		defer resp.Body.Close()
		return fmt.Sprintf("HTTP %s", resp.Status)
	}
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "DOWN " + err.Error()
	}
	_ = conn.Close()
	return "TCP OPEN"
}
