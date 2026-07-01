package tui

import (
	"ai-edr/internal/ui"

	"github.com/charmbracelet/lipgloss"
)

var (
	colorBg      = lipgloss.Color("#1a1b26")
	colorSurface = lipgloss.Color("#24283b")
	colorBorder  = lipgloss.Color("#414868")
	colorAccent  = lipgloss.Color("#7aa2f7")
	colorGreen   = lipgloss.Color("#9ece6a")
	colorYellow  = lipgloss.Color("#e0af68")
	colorRed     = lipgloss.Color("#f7768e")
	colorMuted   = lipgloss.Color("#8b93b5")
	colorText    = lipgloss.Color("#c0caf5")
	colorThought = lipgloss.Color("#a9b1d0") // 思考过程：浅灰，可读但仍弱于正文

	styleApp = lipgloss.NewStyle().Background(colorBg)

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			Background(colorSurface).
			Padding(0, 1)

	styleStatusBar = lipgloss.NewStyle().
			Foreground(colorMuted).
			Background(colorSurface).
			Padding(0, 1)

	styleStep = lipgloss.NewStyle().
			Foreground(colorYellow).
			Bold(true)

	styleThought = lipgloss.NewStyle().
			Foreground(colorThought).
			Italic(true).
			PaddingLeft(2)

	styleStream = lipgloss.NewStyle().
			Foreground(colorThought).
			PaddingLeft(2)

	styleToolBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(0, 1).
			MarginLeft(2)

	styleSubAgentBox = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorYellow).
				Padding(0, 1).
				MarginLeft(2)

	styleTargetBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGreen).
			Padding(0, 1).
			MarginLeft(2)

	styleTodoBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGreen).
			Padding(0, 1).
			MarginLeft(2)

	styleSubAgentResult = lipgloss.NewStyle().
				Foreground(colorMuted).
				Border(lipgloss.NormalBorder()).
				BorderForeground(colorBorder).
				Padding(0, 1).
				MarginLeft(4)

	styleInputLine = lipgloss.NewStyle().
			Foreground(colorText).
			Background(colorSurface)

	styleInputCursor = lipgloss.NewStyle().
				Foreground(colorBg).
				Background(colorAccent).
				Bold(true)

	styleInputBorder = lipgloss.NewStyle().
				Foreground(colorBorder)

	styleInputBorderFocused = lipgloss.NewStyle().
				Foreground(colorAccent)

	styleResult = lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(4)

	styleAnswer = lipgloss.NewStyle().
			Foreground(colorText).
			PaddingLeft(2)

	styleSuccess = lipgloss.NewStyle().Foreground(colorGreen)
	styleError   = lipgloss.NewStyle().Foreground(colorRed)
	styleInfo    = lipgloss.NewStyle().Foreground(colorMuted)

	styleConfirmBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorYellow).
			Background(colorSurface).
			Padding(1, 2).
			Width(60)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)

	// 底部快捷键行：比正文更暗，避免抢眼
	styleHelpHint = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#565f89"))
)

// ConfigureTerminalPreferences applies runtime color preferences after CLI
// flags/env vars have been parsed. Glyph compatibility is handled separately.
func ConfigureTerminalPreferences() {
	if ui.ColorEnabled() {
		return
	}
	styleApp = lipgloss.NewStyle()
	styleHeader = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	styleStatusBar = lipgloss.NewStyle().Padding(0, 1)
	styleStep = lipgloss.NewStyle().Bold(true)
	styleThought = lipgloss.NewStyle().Italic(true).PaddingLeft(2)
	styleStream = lipgloss.NewStyle().PaddingLeft(2)
	styleToolBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).MarginLeft(2)
	styleSubAgentBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).MarginLeft(2)
	styleTargetBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).MarginLeft(2)
	styleTodoBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).MarginLeft(2)
	styleSubAgentResult = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(0, 1).MarginLeft(4)
	styleInputLine = lipgloss.NewStyle()
	styleInputCursor = lipgloss.NewStyle().Reverse(true).Bold(true)
	styleInputBorder = lipgloss.NewStyle()
	styleInputBorderFocused = lipgloss.NewStyle().Bold(true)
	styleResult = lipgloss.NewStyle().PaddingLeft(4)
	styleAnswer = lipgloss.NewStyle().PaddingLeft(2)
	styleSuccess = lipgloss.NewStyle()
	styleError = lipgloss.NewStyle()
	styleInfo = lipgloss.NewStyle()
	styleConfirmBox = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).Padding(1, 2).Width(60)
	styleHelp = lipgloss.NewStyle().Italic(true)
	styleHelpHint = lipgloss.NewStyle()

	styleBannerBorder = lipgloss.NewStyle()
	styleBannerRobot = lipgloss.NewStyle()
	styleBannerRobotHi = lipgloss.NewStyle().Bold(true)
	styleBannerBrand = lipgloss.NewStyle().Bold(true)
	styleBannerBadge = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	styleBannerTagline = lipgloss.NewStyle()
	styleBannerHeading = lipgloss.NewStyle().Bold(true)
	styleBannerLabel = lipgloss.NewStyle()
	styleBannerText = lipgloss.NewStyle()
	styleBannerDivider = lipgloss.NewStyle()
	styleSelection = lipgloss.NewStyle().Reverse(true)
	styleAccent = lipgloss.NewStyle().Bold(true)

	mdH1Style = lipgloss.NewStyle().Bold(true)
	mdH2Style = lipgloss.NewStyle().Bold(true)
	mdH3Style = lipgloss.NewStyle().Bold(true)
	mdBoldStyle = lipgloss.NewStyle().Bold(true)
	mdCodeStyle = lipgloss.NewStyle()
	mdMutedStyle = lipgloss.NewStyle()
	mdTableBorder = lipgloss.NewStyle()
	mdTableHeader = lipgloss.NewStyle().Bold(true)
	mdListMarker = lipgloss.NewStyle().Bold(true)
}
