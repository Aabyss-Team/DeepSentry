package tui

import (
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func isClipboardPasteShortcut(msg tea.KeyMsg) bool {
	if msg.Type == tea.KeyCtrlV {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(msg.String())) {
	case "ctrl+v", "ctrl+shift+v", "cmd+v", "cmd+shift+v", "super+v", "super+shift+v":
		return true
	default:
		return false
	}
}

func pasteShortcutHelp() string {
	if runtime.GOOS == "darwin" {
		return "⌘V/Ctrl+V 粘贴图片/文本"
	}
	return "Ctrl+V 粘贴图片/文本"
}
