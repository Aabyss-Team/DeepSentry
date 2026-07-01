//go:build windows
// +build windows

package main

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// enableWindowsANSI 负责 Windows 平台的控制台初始化：
// 1. 强制开启 UTF-8 输入/输出编码 (解决中文乱码)
// 2. 强制开启虚拟终端处理 (解决颜色与 TUI 按键/鼠标乱码)
func enableWindowsANSI() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// --- 1. 设置控制台输入/输出代码页为 UTF-8 (Code Page 65001) ---
	setConsoleCP := kernel32.NewProc("SetConsoleCP")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	setConsoleCP.Call(uintptr(65001))
	setConsoleOutputCP.Call(uintptr(65001))

	// --- 2. 开启 ANSI 颜色支持 (Virtual Terminal Processing) ---
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		windows.SetConsoleMode(stdout, mode)
	}

	stdin := windows.Handle(os.Stdin.Fd())
	if err := windows.GetConsoleMode(stdin, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
		windows.SetConsoleMode(stdin, mode)
	}
}

func configureDetachedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
