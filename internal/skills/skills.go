package skills

import (
	"ai-edr/internal/security" // 确保这里的 module 名和你 go.mod 里的一致
	"fmt"
	"os/exec"
)

// SkillResult 统一返回格式
type SkillResult struct {
	ToolName string
	Content  string
}

// 1. CheckSSHLogs 排查 SSH 爆破和登录情况
func CheckSSHLogs(lines int) string {
	// 修复：之前定义的 cmd 变量没用到，直接删掉
	// 我们直接执行命令

	// 尝试读取最后几行登录失败记录
	// 注意：lastb 通常需要 root 权限，如果在 Mac 普通用户下可能没输出
	out, err := exec.Command("bash", "-c", "lastb | head -10").CombinedOutput()
	if err != nil {
		return "无法读取 SSH 失败日志 (可能需要 root 权限)"
	}

	successOut, _ := exec.Command("bash", "-c", "last | head -5").CombinedOutput()

	return fmt.Sprintf("【最近登录失败记录】:\n%s\n【最近登录成功记录】:\n%s", string(out), string(successOut))
}

// 2. CheckSystemUsers 检查系统用户和特权用户
func CheckSystemUsers() string {
	// 查找 UID 为 0 的用户 (特权用户)
	out, _ := exec.Command("bash", "-c", "awk -F: '$3==0 {print $1}' /etc/passwd").CombinedOutput()

	// 查找有登录权限的用户 (/bin/bash)
	loginUsers, _ := exec.Command("bash", "-c", "grep '/bin/bash' /etc/passwd | cut -d: -f1").CombinedOutput()

	return fmt.Sprintf("【特权用户(UID=0)】:\n%s\n【可登录用户】:\n%s", string(out), string(loginUsers))
}

// 3. CheckCronJobs 查看计划任务
func CheckCronJobs() string {
	// 查看 /etc/crontab
	sysCron, err := exec.Command("cat", "/etc/crontab").CombinedOutput()
	if err != nil {
		return "无法读取 /etc/crontab"
	}
	return fmt.Sprintf("【系统级计划任务 /etc/crontab】:\n%s", string(sysCron))
}

// 4. RunSafeQuery 执行用户指定的任意（安全）查询
func RunSafeQuery(bin string, args ...string) string {
	out, err := security.SafeExec(bin, args...)
	if err != nil {
		return fmt.Sprintf("执行被阻断或失败: %v", err)
	}
	return out
}
