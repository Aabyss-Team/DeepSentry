package tui

import (
	"os"
	"strings"

	"ai-edr/internal/ui"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type terminalPalette struct {
	bg, surface, border, accent lipgloss.Color
	green, yellow, red          lipgloss.Color
	muted, text, thought, help  lipgloss.Color
	robot                       lipgloss.Color
}

func darkTerminalPalette() terminalPalette {
	return terminalPalette{
		bg: "#1a1b26", surface: "#24283b", border: "#414868", accent: "#7aa2f7",
		green: "#9ece6a", yellow: "#e0af68", red: "#f7768e",
		muted: "#8b93b5", text: "#c0caf5", thought: "#a9b1d0", help: "#8b93b5",
		robot: "#5c7cfa",
	}
}

func lightTerminalPalette() terminalPalette {
	return terminalPalette{
		bg: "#f7f8fc", surface: "#e7ebf3", border: "#8a96aa", accent: "#2457c5",
		green: "#18794e", yellow: "#8a5700", red: "#c01c28",
		muted: "#536072", text: "#1f2430", thought: "#465164", help: "#536072",
		robot: "#315fd4",
	}
}

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
	colorThought = lipgloss.Color("#a9b1d0")

	styleApp                lipgloss.Style
	styleHeader             lipgloss.Style
	styleStatusBar          lipgloss.Style
	styleStep               lipgloss.Style
	styleThought            lipgloss.Style
	styleStream             lipgloss.Style
	styleToolBox            lipgloss.Style
	styleSubAgentBox        lipgloss.Style
	styleTargetBox          lipgloss.Style
	styleTodoBox            lipgloss.Style
	styleSubAgentResult     lipgloss.Style
	styleInputLine          lipgloss.Style
	styleInputCursor        lipgloss.Style
	styleInputBorder        lipgloss.Style
	styleInputBorderFocused lipgloss.Style
	styleResult             lipgloss.Style
	styleAnswer             lipgloss.Style
	styleSuccess            lipgloss.Style
	styleError              lipgloss.Style
	styleInfo               lipgloss.Style
	styleConfirmBox         lipgloss.Style
	styleHelp               lipgloss.Style
	styleHelpHint           lipgloss.Style
)

func init() {
	applyTerminalPalette(darkTerminalPalette())
}

// NormalizeTerminalTheme validates a user/config value without probing the
// terminal. Empty values intentionally mean auto so existing configs adapt.
func NormalizeTerminalTheme(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return "auto", true
	case "dark":
		return "dark", true
	case "light":
		return "light", true
	default:
		return "", false
	}
}

// ConfigureTerminalPreferences applies color and theme preferences before the
// TUI starts. auto queries the terminal's OSC 11 background color (with
// COLORFGBG fallback) and chooses a contrast-safe palette. Explicit dark/light
// remains available for terminals that do not answer background queries.
func ConfigureTerminalPreferences(requested ...string) string {
	raw := ""
	if len(requested) > 0 {
		raw = requested[0]
	}
	if strings.TrimSpace(raw) == "" {
		raw = os.Getenv("DEEPSENTRY_TERMINAL_THEME")
	}
	theme, ok := NormalizeTerminalTheme(raw)
	if !ok {
		theme = "auto"
	}
	resolved := theme
	if theme == "auto" {
		resolved = "dark"
		if !termenv.HasDarkBackground() {
			resolved = "light"
		}
	}

	if !ui.ColorEnabled() {
		applyNoColorStyles()
		return resolved
	}
	if resolved == "light" {
		applyTerminalPalette(lightTerminalPalette())
	} else {
		applyTerminalPalette(darkTerminalPalette())
	}
	return resolved
}

func applyTerminalPalette(p terminalPalette) {
	colorBg, colorSurface, colorBorder, colorAccent = p.bg, p.surface, p.border, p.accent
	colorGreen, colorYellow, colorRed = p.green, p.yellow, p.red
	colorMuted, colorText, colorThought = p.muted, p.text, p.thought

	styleApp = lipgloss.NewStyle().Background(colorBg)
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Background(colorSurface).Padding(0, 1)
	styleStatusBar = lipgloss.NewStyle().Foreground(colorMuted).Background(colorSurface).Padding(0, 1)
	styleStep = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	styleThought = lipgloss.NewStyle().Foreground(colorThought).Italic(true).PaddingLeft(2)
	styleStream = lipgloss.NewStyle().Foreground(colorThought).PaddingLeft(2)
	styleToolBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorAccent).Padding(0, 1).MarginLeft(2)
	styleSubAgentBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorYellow).Padding(0, 1).MarginLeft(2)
	styleTargetBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorGreen).Padding(0, 1).MarginLeft(2)
	styleTodoBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorGreen).Padding(0, 1).MarginLeft(2)
	styleSubAgentResult = lipgloss.NewStyle().Foreground(colorMuted).Border(lipgloss.NormalBorder()).BorderForeground(colorBorder).Padding(0, 1).MarginLeft(4)
	styleInputLine = lipgloss.NewStyle().Foreground(colorText).Background(colorSurface)
	styleInputCursor = lipgloss.NewStyle().Foreground(colorBg).Background(colorAccent).Bold(true)
	styleInputBorder = lipgloss.NewStyle().Foreground(colorBorder)
	styleInputBorderFocused = lipgloss.NewStyle().Foreground(colorAccent)
	styleResult = lipgloss.NewStyle().Foreground(colorMuted).PaddingLeft(4)
	styleAnswer = lipgloss.NewStyle().Foreground(colorText).PaddingLeft(2)
	styleSuccess = lipgloss.NewStyle().Foreground(colorGreen)
	styleError = lipgloss.NewStyle().Foreground(colorRed)
	styleInfo = lipgloss.NewStyle().Foreground(colorMuted)
	styleConfirmBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorYellow).Background(colorSurface).Padding(1, 2).MarginLeft(2)
	styleHelp = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)
	styleHelpHint = lipgloss.NewStyle().Foreground(p.help)

	styleBannerBorder = lipgloss.NewStyle().Foreground(colorAccent)
	styleBannerRobot = lipgloss.NewStyle().Foreground(p.robot)
	styleBannerRobotHi = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleBannerBrand = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	styleBannerBadge = lipgloss.NewStyle().Bold(true).Foreground(colorBg).Background(colorAccent).Padding(0, 1)
	styleBannerTagline = lipgloss.NewStyle().Foreground(colorMuted)
	styleBannerHeading = lipgloss.NewStyle().Bold(true).Foreground(colorYellow)
	styleBannerLabel = lipgloss.NewStyle().Foreground(colorMuted)
	styleBannerText = lipgloss.NewStyle().Foreground(colorText)
	styleBannerDivider = lipgloss.NewStyle().Foreground(colorBorder)
	styleSelection = lipgloss.NewStyle().Foreground(colorBg).Background(colorAccent)
	styleAccent = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)

	mdH1Style = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	mdH2Style = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	mdH3Style = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	mdBoldStyle = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	mdCodeStyle = lipgloss.NewStyle().Foreground(colorYellow).Background(colorSurface)
	mdMutedStyle = lipgloss.NewStyle().Foreground(colorMuted)
	mdTableBorder = lipgloss.NewStyle().Foreground(colorBorder)
	mdTableHeader = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	mdListMarker = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
}

func applyNoColorStyles() {
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
	styleConfirmBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).MarginLeft(2)
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
