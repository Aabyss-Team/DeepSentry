package builtin

import (
	"strings"
	"testing"
)

func TestCompetitionAnswerCheckFindsEvidenceAndRequiredSections(t *testing.T) {
	answer := `【任务状态】已完成
【结论】端口无物理故障。
【关键证据】
1. display interface brief -> GE1/0/1 up/up。
2. display interface GE1/0/1 -> input rate 10 bps, 0 errors。
3. ping 10.0.0.1 -> 0% loss, 1 ms。
【处置/答案】无需修改配置。
【复验】重复 ping 仍为 0% loss。
【AI 复核与纠错】已否定“端口 down”假设。
【风险与回滚】无变更，无需回滚。`
	out, err := CompetitionAnswerCheck("排查端口故障", answer)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"估算=100/100", "缺失=无", "AI纠错=true", "顺序正确=true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestCompetitionAnswerCheckRejectsEmptyDraft(t *testing.T) {
	if _, err := CompetitionAnswerCheck("task", " "); err == nil {
		t.Fatal("expected empty answer error")
	}
}
