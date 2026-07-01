package tui

import (
	"fmt"
	"strings"

	"ai-edr/internal/harness"
	"ai-edr/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
)

type pickResultMsg struct {
	id     string
	cancel bool
}

// SessionPickerModel 会话选择器
type SessionPickerModel struct {
	items  []harness.SessionSummary
	cursor int
	width  int
	done   chan pickResultMsg
}

func newSessionPicker(items []harness.SessionSummary, done chan pickResultMsg) SessionPickerModel {
	return SessionPickerModel{items: items, done: done}
}

func (m SessionPickerModel) Init() tea.Cmd { return nil }

func (m SessionPickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.done <- pickResultMsg{cancel: true}
			return m, tea.Quit
		case "enter":
			if len(m.items) == 0 {
				m.done <- pickResultMsg{}
				return m, tea.Quit
			}
			m.done <- pickResultMsg{id: m.items[m.cursor].ID}
			return m, tea.Quit
		case "n":
			m.done <- pickResultMsg{}
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		}
	}
	return m, nil
}

func (m SessionPickerModel) View() string {
	var b strings.Builder
	b.WriteString(styleHeader.Width(max(60, m.width-2)).Render(" " + ui.Prefix("♻️", "[RESUME]") + "选择要恢复的会话"))
	b.WriteString("\n\n")
	if len(m.items) == 0 {
		b.WriteString(styleInfo.Render("  无可恢复会话。按 N 开始新任务。"))
	} else {
		for i, it := range m.items {
			label := fmt.Sprintf(" %s  step:%d  %s", it.ID, it.StepNum, it.SavedAt.Format("01-02 15:04"))
			if it.Goal != "" {
				label += "  · " + truncateStr(it.Goal, 40)
			}
			if i == m.cursor {
				cursor := "▸ "
				if ui.PlainTextMode() {
					cursor = "> "
				}
				b.WriteString(styleAccent.Render(cursor+label) + "\n")
			} else {
				b.WriteString(styleInfo.Render("  "+label) + "\n")
			}
		}
	}
	b.WriteString("\n" + styleHelp.Render("  ↑↓ 选择 · Enter 恢复 · N 新会话 · Esc 取消"))
	return styleApp.Render(b.String())
}

// PickSession 返回 sessionID（空=新会话），cancelled 表示用户取消
func PickSession() (sessionID string, cancelled bool, err error) {
	items, err := harness.ListSessionSummaries()
	if err != nil {
		return "", false, err
	}
	done := make(chan pickResultMsg, 1)
	m := newSessionPicker(items, done)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return "", false, err
	}
	r := <-done
	return r.id, r.cancel, nil
}
