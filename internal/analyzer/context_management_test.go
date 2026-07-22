package analyzer

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func longHistoryForTest() []Message {
	history := []Message{{Role: "user", Content: "排查生产 Web 入侵并保留完整证据链"}}
	for i := 0; i < 32; i++ {
		history = append(history,
			Message{Role: "assistant", Content: fmt.Sprintf(`{"action":"execute","command":"check-%d"}`, i)},
			Message{Role: "user", Content: fmt.Sprintf("Output:\nstep=%d %s", i, strings.Repeat("evidence ", 300))},
		)
	}
	return history
}

func TestManageHistoryContextPreservesGoalPinnedCluesAndRecentTail(t *testing.T) {
	history := longHistoryForTest()
	history = append(history[:4], append([]Message{{Role: "user", Content: "补充：只读排查，不要修改目标文件"}}, history[4:]...)...)
	last := history[len(history)-1].Content
	called := false
	compacted, err := ManageHistoryContextWithOptions(&history, ContextManageOptions{
		PinnedContext: "[IP] 10.20.30.40 — 已验证 C2\n[PATH] /var/www/html/a.php",
		Summarize: func(_ context.Context, messages []Message) (string, error) {
			called = true
			total := estimateHistoryChars(messages)
			if total > 60000 {
				t.Fatalf("summary request exceeded bounded input: %d", total)
			}
			joined := ""
			for _, message := range messages {
				joined += message.Content
			}
			for _, want := range []string{"排查生产 Web 入侵", "只读排查", "10.20.30.40", "/var/www/html/a.php"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("summary request lost pinned context %q", want)
				}
			}
			return "已完成入口排查；待关联网络证据。", nil
		},
	})
	if err != nil || !compacted || !called {
		t.Fatalf("compaction failed: compacted=%v called=%v err=%v", compacted, called, err)
	}
	if len(history) != contextCompactKeepRecent+1 {
		t.Fatalf("history len=%d want %d", len(history), contextCompactKeepRecent+1)
	}
	for _, want := range []string{"【原始用户目标】", "排查生产 Web 入侵", "最新用户补充", "只读排查", "10.20.30.40", "待关联网络证据"} {
		if !strings.Contains(history[0].Content, want) {
			t.Fatalf("summary envelope lost %q:\n%s", want, history[0].Content)
		}
	}
	if history[len(history)-1].Content != last {
		t.Fatal("recent history tail changed during compaction")
	}
}

func TestManageHistoryContextCancellationDoesNotMutateHistory(t *testing.T) {
	history := longHistoryForTest()
	original := append([]Message(nil), history...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	compacted, err := ManageHistoryContextWithOptions(&history, ContextManageOptions{
		Context: ctx,
		Summarize: func(ctx context.Context, _ []Message) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		},
	})
	if compacted || !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation result compacted=%v err=%v", compacted, err)
	}
	if len(history) != len(original) || !reflect.DeepEqual(history[0], original[0]) || !reflect.DeepEqual(history[len(history)-1], original[len(original)-1]) {
		t.Fatal("failed/cancelled compaction mutated live history")
	}
}

func TestManageHistoryContextAvoidsSummarizingManyTinyTurns(t *testing.T) {
	var history []Message
	for i := 0; i < 70; i++ {
		history = append(history, Message{Role: "user", Content: fmt.Sprintf("短消息-%d", i)})
	}
	called := false
	compacted, err := ManageHistoryContextWithOptions(&history, ContextManageOptions{
		Summarize: func(context.Context, []Message) (string, error) {
			called = true
			return "unexpected", nil
		},
	})
	if err != nil || compacted || called {
		t.Fatalf("tiny turns should not spend a summary call: compacted=%v called=%v err=%v", compacted, called, err)
	}
}

func TestTruncateHistoryFallbackPreservesGoalAndPinnedClues(t *testing.T) {
	history := longHistoryForTest()
	history = append(history[:1], append([]Message{{Role: "system", Content: "【前情提要】已确认旧证据 EVIDENCE-OLD"}}, history[1:]...)...)
	history = append(history[:5], append([]Message{{Role: "user", Content: "补充：只读，不做修复"}}, history[5:]...)...)
	last := history[len(history)-1]
	TruncateHistoryFallbackWithHints(&history, 8, "[CVE] CVE-2026-12345")
	if len(history) != 9 {
		t.Fatalf("fallback len=%d want 9", len(history))
	}
	for _, want := range []string{"排查生产 Web 入侵", "CVE-2026-12345", "最近 8 条", "EVIDENCE-OLD", "只读，不做修复"} {
		if !strings.Contains(history[0].Content, want) {
			t.Fatalf("fallback lost %q:\n%s", want, history[0].Content)
		}
	}
	if !reflect.DeepEqual(history[len(history)-1], last) {
		t.Fatal("fallback lost latest message")
	}
}

func TestManageHistoryContextLargeWindowDoesNotCompactEarly(t *testing.T) {
	history := longHistoryForTest()
	called := false
	compacted, err := ManageHistoryContextWithOptions(&history, ContextManageOptions{
		HistoryBudgetTokens: 800_000,
		Summarize: func(context.Context, []Message) (string, error) {
			called = true
			return "unexpected", nil
		},
	})
	if err != nil || compacted || called {
		t.Fatalf("large context was prematurely compacted: compacted=%v called=%v err=%v", compacted, called, err)
	}
}

func TestManageHistoryContextSplitsGiantMessageWithoutDroppingMiddle(t *testing.T) {
	middle := "MIDDLE-EVIDENCE-SENTINEL"
	giant := strings.Repeat("A", 18_000) + middle + strings.Repeat("Z", 18_000)
	history := []Message{
		{Role: "user", Content: "分析这份巨大日志"},
		{Role: "user", Content: giant},
		{Role: "assistant", Content: `{"action":"execute","command":"next"}`},
	}
	seenMiddle := false
	calls := 0
	compacted, err := ManageHistoryContextWithOptions(&history, ContextManageOptions{
		HistoryBudgetTokens: 2_000,
		KeepRecent:          8,
		SummaryChunkTokens:  1_000,
		Summarize: func(_ context.Context, messages []Message) (string, error) {
			calls++
			for _, message := range messages {
				if strings.Contains(message.Content, middle) {
					seenMiddle = true
				}
			}
			return fmt.Sprintf("分段摘要-%d", calls), nil
		},
	})
	if err != nil || !compacted || calls < 2 || !seenMiddle {
		t.Fatalf("giant message compaction failed: compacted=%v calls=%d middle=%v err=%v", compacted, calls, seenMiddle, err)
	}
}

func TestEstimateTextTokensTreatsCJKAndASCIIConservatively(t *testing.T) {
	if got := EstimateTextTokens("中文测试"); got != 4 {
		t.Fatalf("CJK estimate=%d want 4", got)
	}
	if got := EstimateTextTokens("abcdefghijkl"); got != 4 {
		t.Fatalf("ASCII estimate=%d want 4", got)
	}
}
