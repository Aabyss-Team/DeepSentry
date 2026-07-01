package ui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/term"
)

// ResetTerminalState 恢复终端到正常 shell 模式。
// survey / TUI / ANSI 流式输出可能留下 raw mode、鼠标模式、备用屏或 bracketed paste，导致 zsh 无法识别后续命令。
func ResetTerminalState() {
	if !term.IsTerminal(int(os.Stdout.Fd())) && !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	const seq = "\x1b[0m" +
		"\x1b[?25h" + // show cursor
		"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" + // mouse modes
		"\x1b[?2004l" + // bracketed paste
		"\x1b[?1049l\x1b[?47l" // alt screen
	_, _ = fmt.Fprint(os.Stdout, seq)
	_, _ = fmt.Fprint(os.Stderr, seq)
	// survey 结束后光标常停在行中列，仅 \n 会换行但不回列首，导致下一行输出右偏
	_, _ = fmt.Fprint(os.Stdout, "\r\n")
	if runtime.GOOS != "windows" && term.IsTerminal(int(os.Stdin.Fd())) {
		args := sttySaneArgs(runtime.GOOS)
		_ = exec.Command("stty", args...).Run()
	}
}

func sttySaneArgs(goos string) []string {
	if goos == "darwin" || goos == "freebsd" || goos == "openbsd" || goos == "netbsd" {
		return []string{"-f", "/dev/tty", "sane"}
	}
	return []string{"-F", "/dev/tty", "sane"}
}

// Exit 在退出前恢复终端（os.Exit 不会执行 defer）。
func Exit(code int) {
	ResetTerminalState()
	os.Exit(code)
}
