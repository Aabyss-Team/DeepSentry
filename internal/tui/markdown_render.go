package tui

import (
	"regexp"
	"strings"
	"unicode"

	"ai-edr/internal/ui"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

var (
	mdH1Style      = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	mdH2Style      = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	mdH3Style      = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	mdBoldStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	mdCodeStyle    = lipgloss.NewStyle().Foreground(colorYellow).Background(colorSurface)
	mdMutedStyle   = lipgloss.NewStyle().Foreground(colorMuted)
	mdTableBorder  = lipgloss.NewStyle().Foreground(colorBorder)
	mdTableHeader  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	mdListMarker   = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	mdNumberedList = regexp.MustCompile(`^\s*(\d+)[.)]\s+(.+)$`)
)

func renderMarkdownReport(markdown string, width int) string {
	if width <= 0 {
		width = 80
	}
	innerW := width - styleAnswer.GetHorizontalFrameSize()
	if innerW < 20 {
		innerW = 20
	}
	rendered := renderMarkdownBlocks(markdown, innerW)
	return styleAnswer.Width(innerW).Render(rendered)
}

func renderMarkdownBlocks(markdown string, width int) string {
	markdown = strings.ReplaceAll(markdown, "\r\n", "\n")
	markdown = strings.ReplaceAll(markdown, "\r", "\n")
	lines := strings.Split(strings.TrimSpace(markdown), "\n")
	out := make([]string, 0, len(lines))

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			continue
		}

		if strings.HasPrefix(trimmed, "```") {
			code := make([]string, 0)
			i++
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				code = append(code, runewidth.Truncate(lines[i], width, "…"))
				i++
			}
			out = append(out, renderCodeBlock(code, width))
			continue
		}

		if isMarkdownTableStart(lines, i) {
			tableLines := []string{lines[i], lines[i+1]}
			i += 2
			for i < len(lines) && isMarkdownTableLine(lines[i]) {
				tableLines = append(tableLines, lines[i])
				i++
			}
			i--
			out = append(out, renderMarkdownTable(tableLines, width)...)
			continue
		}

		if level, text, ok := parseMarkdownHeading(trimmed); ok {
			if len(out) > 0 && out[len(out)-1] != "" && level <= 2 {
				out = append(out, "")
			}
			out = append(out, renderMarkdownHeading(level, text, width))
			continue
		}

		if marker, text, ok := parseMarkdownList(trimmed); ok {
			out = append(out, renderMarkdownListItem(marker, text, width))
			continue
		}

		plain := markdownInlinePlain(trimmed)
		if runewidth.StringWidth(plain) <= width {
			out = append(out, renderInlineMarkdown(trimmed))
			continue
		}
		for _, wrapped := range strings.Split(wrapDisplay(plain, width), "\n") {
			out = append(out, wrapped)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func parseMarkdownHeading(line string) (int, string, bool) {
	if !strings.HasPrefix(line, "#") {
		return 0, "", false
	}
	level := 0
	for level < len(line) && level < 6 && line[level] == '#' {
		level++
	}
	if level == 0 || level >= len(line) || line[level] != ' ' {
		return 0, "", false
	}
	return level, strings.TrimSpace(line[level:]), true
}

func renderMarkdownHeading(level int, text string, width int) string {
	text = normalizeMarkdownHeadingText(markdownInlinePlain(text))
	switch {
	case level <= 1:
		marker := "=="
		label := runewidth.Truncate(text, max(4, width-runewidth.StringWidth(marker)-1), "…")
		return mdH1Style.Render(marker + " " + label)
	case level == 2:
		marker := "--"
		label := runewidth.Truncate(text, max(4, width-runewidth.StringWidth(marker)-1), "…")
		return mdH2Style.Render(marker + " " + label)
	default:
		marker := ">"
		label := runewidth.Truncate(text, max(4, width-runewidth.StringWidth(marker)-1), "…")
		return mdH3Style.Render(marker + " " + label)
	}
}

func normalizeMarkdownHeadingText(text string) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if text == "" {
		return text
	}
	runes := []rune(text)
	if len(runes) < 2 {
		return text
	}
	if !isMarkdownIconPrefix(runes[0]) {
		return text
	}
	if unicode.IsSpace(runes[1]) {
		return text
	}
	return string(runes[0]) + " " + string(runes[1:])
}

func isMarkdownIconPrefix(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	if unicode.IsSymbol(r) {
		return true
	}
	return runewidth.RuneWidth(r) >= 2
}

func parseMarkdownList(line string) (string, string, bool) {
	if len(line) >= 2 {
		prefix := line[:2]
		if prefix == "- " || prefix == "* " || prefix == "+ " {
			return "•", strings.TrimSpace(line[2:]), true
		}
	}
	if m := mdNumberedList.FindStringSubmatch(line); len(m) == 3 {
		return m[1] + ".", strings.TrimSpace(m[2]), true
	}
	return "", "", false
}

func renderMarkdownListItem(marker, text string, width int) string {
	markerW := runewidth.StringWidth(marker) + 2
	bodyW := max(8, width-markerW)
	wrapped := strings.Split(wrapDisplay(markdownInlinePlain(text), bodyW), "\n")
	for i, line := range wrapped {
		if i == 0 {
			wrapped[i] = mdListMarker.Render(marker) + " " + renderInlineMarkdown(line)
		} else {
			wrapped[i] = strings.Repeat(" ", markerW) + renderInlineMarkdown(line)
		}
	}
	return strings.Join(wrapped, "\n")
}

func renderInlineMarkdown(line string) string {
	var b strings.Builder
	for len(line) > 0 {
		codeStart := strings.Index(line, "`")
		boldStart := strings.Index(line, "**")
		switch {
		case codeStart >= 0 && (boldStart < 0 || codeStart < boldStart):
			b.WriteString(line[:codeStart])
			rest := line[codeStart+1:]
			if end := strings.Index(rest, "`"); end >= 0 {
				b.WriteString(mdCodeStyle.Render(rest[:end]))
				line = rest[end+1:]
			} else {
				b.WriteString("`" + rest)
				line = ""
			}
		case boldStart >= 0:
			b.WriteString(line[:boldStart])
			rest := line[boldStart+2:]
			if end := strings.Index(rest, "**"); end >= 0 {
				b.WriteString(mdBoldStyle.Render(rest[:end]))
				line = rest[end+2:]
			} else {
				b.WriteString("**" + rest)
				line = ""
			}
		default:
			b.WriteString(line)
			line = ""
		}
	}
	return b.String()
}

func markdownInlinePlain(line string) string {
	line = strings.ReplaceAll(line, "**", "")
	line = strings.ReplaceAll(line, "`", "")
	return ui.TerminalText(line)
}

func renderCodeBlock(lines []string, width int) string {
	if len(lines) == 0 {
		return ""
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, mdCodeStyle.Render(fitPlainLine(line, width)))
	}
	return strings.Join(out, "\n")
}

func isMarkdownTableStart(lines []string, i int) bool {
	return i+1 < len(lines) && isMarkdownTableLine(lines[i]) && isMarkdownTableSeparator(lines[i+1])
}

func isMarkdownTableLine(line string) bool {
	line = strings.TrimSpace(line)
	return strings.Count(line, "|") >= 2
}

func isMarkdownTableSeparator(line string) bool {
	cells := splitMarkdownTableRow(line)
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			return false
		}
		cell = strings.Trim(cell, ":")
		if cell == "" || strings.Trim(cell, "-") != "" {
			return false
		}
	}
	return true
}

func splitMarkdownTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(markdownInlinePlain(part)))
	}
	return cells
}

func renderMarkdownTable(lines []string, width int) []string {
	if len(lines) < 2 {
		return lines
	}
	rows := make([][]string, 0, len(lines)-1)
	for i, line := range lines {
		if i == 1 {
			continue
		}
		rows = append(rows, splitMarkdownTableRow(line))
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return []string{strings.Join(lines, "\n")}
	}
	cols := len(rows[0])
	for i := range rows {
		for len(rows[i]) < cols {
			rows[i] = append(rows[i], "")
		}
		if len(rows[i]) > cols {
			rows[i] = rows[i][:cols]
		}
	}
	tableW := max(20, width-2)
	widths := markdownTableWidths(rows, tableW)
	out := make([]string, 0, len(rows)+3)
	prefix := "  "
	out = append(out, prefix+tableBorderLine("top", widths))
	out = append(out, prefix+tableRow(rows[0], widths, true))
	out = append(out, prefix+tableBorderLine("mid", widths))
	for _, row := range rows[1:] {
		out = append(out, prefix+tableRow(row, widths, false))
	}
	out = append(out, prefix+tableBorderLine("bottom", widths))
	return out
}

func markdownTableWidths(rows [][]string, maxWidth int) []int {
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			w := runewidth.StringWidth(cell)
			if w > widths[i] {
				widths[i] = w
			}
		}
	}
	for i := range widths {
		if widths[i] < 4 {
			widths[i] = 4
		}
		if widths[i] > 32 {
			widths[i] = 32
		}
	}
	for tableTotalWidth(widths) > maxWidth && len(widths) > 0 {
		idx := widestColumn(widths)
		if widths[idx] <= 6 {
			break
		}
		widths[idx]--
	}
	return widths
}

func tableTotalWidth(widths []int) int {
	total := 1
	for _, w := range widths {
		total += w + 3
	}
	return total
}

func widestColumn(widths []int) int {
	idx := 0
	for i, w := range widths {
		if w > widths[idx] {
			idx = i
		}
	}
	return idx
}

func tableBorderLine(kind string, widths []int) string {
	left, mid, right := "├", "┼", "┤"
	if ui.PlainTextMode() {
		left, mid, right = "+", "+", "+"
	} else {
		switch kind {
		case "top":
			left, mid, right = "╭", "┬", "╮"
		case "bottom":
			left, mid, right = "╰", "┴", "╯"
		}
	}
	if ui.PlainTextMode() {
		parts := make([]string, 0, len(widths))
		for _, w := range widths {
			parts = append(parts, strings.Repeat("-", w+2))
		}
		return mdTableBorder.Render(left + strings.Join(parts, mid) + right)
	}
	parts := make([]string, 0, len(widths))
	for _, w := range widths {
		parts = append(parts, strings.Repeat("─", w+2))
	}
	return mdTableBorder.Render(left + strings.Join(parts, mid) + right)
}

func tableRow(cells []string, widths []int, header bool) string {
	var b strings.Builder
	pipe := mdTableBorder.Render("|")
	if !ui.PlainTextMode() {
		pipe = mdTableBorder.Render("│")
	}
	b.WriteString(pipe)
	for i, w := range widths {
		cell := ""
		if i < len(cells) {
			cell = fitPlainLine(cells[i], w)
		}
		content := " " + cell + " "
		if header {
			content = mdTableHeader.Render(content)
		}
		b.WriteString(content)
		b.WriteString(pipe)
	}
	return b.String()
}

func fitPlainLine(s string, width int) string {
	s = ui.TerminalText(s)
	if runewidth.StringWidth(s) > width {
		s = runewidth.Truncate(s, width, "…")
	}
	if gap := width - runewidth.StringWidth(s); gap > 0 {
		s += strings.Repeat(" ", gap)
	}
	return s
}
