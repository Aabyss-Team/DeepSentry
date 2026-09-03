package tui

// macosCmdVMsg is sent when macOS HID polling sees Command+V while this
// DeepSentry session's host window is frontmost. The terminal itself usually
// swallows that chord for images, so the TUI never gets a key event; this
// message is the replacement trigger. Other apps (Cursor, browsers, another
// terminal tab) must not fire it.
type macosCmdVMsg struct{}

type macosCmdVIgnoredMsg struct{}
