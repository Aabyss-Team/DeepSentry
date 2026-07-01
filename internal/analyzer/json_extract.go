package analyzer

import "strings"

// extractJSONPayload 从混合文本/Markdown 中提取 JSON 对象，并返回前置说明文字
func extractJSONPayload(s string) (jsonPart, prose string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	// 优先：Markdown ```json ... ``` 或 ``` ... ```
	if block, before := extractMarkdownJSONBlock(s); block != "" {
		if obj := extractBalancedJSONObject(block); obj != "" {
			return obj, strings.TrimSpace(before)
		}
	}

	// 其次：文本中首个平衡 JSON 对象
	if obj := extractBalancedJSONObject(s); obj != "" {
		before := strings.TrimSpace(s[:strings.Index(s, obj)])
		return obj, before
	}

	return s, ""
}

func extractMarkdownJSONBlock(s string) (block, before string) {
	bestIdx := -1
	bestOpener := ""
	for _, opener := range []string{"```json", "```JSON", "```"} {
		if idx := strings.Index(s, opener); idx != -1 && (bestIdx == -1 || idx < bestIdx) {
			bestIdx = idx
			bestOpener = opener
		}
	}
	if bestIdx == -1 {
		return "", ""
	}
	before = s[:bestIdx]
	rest := s[bestIdx+len(bestOpener):]
	end := strings.Index(rest, "```")
	if end == -1 {
		return "", before
	}
	return strings.TrimSpace(rest[:end]), before
}

// extractBalancedJSONObject 提取第一个平衡的 {...} 片段
func extractBalancedJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString {
			if escape {
				escape = false
				continue
			}
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func normalizeProseThought(prose string) string {
	prose = strings.TrimSpace(prose)
	if prose == "" {
		return ""
	}
	// 去掉常见前缀符号
	prose = strings.TrimPrefix(prose, "💭")
	prose = strings.TrimSpace(prose)
	if len(prose) > 500 {
		prose = prose[:500] + "..."
	}
	return prose
}
