package tui

// ChromeContentWidth 与 viewport / 输入框对齐的可视内容宽度（body 左右各 1 列 padding）。
func ChromeContentWidth(termW int) int {
	if termW <= 0 {
		termW = 80
	}
	return max(40, termW-2)
}
