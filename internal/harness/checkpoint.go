package harness

import (
	"ai-edr/internal/analyzer"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CheckpointData 会话 checkpoint 快照
type CheckpointData struct {
	SessionID    string             `json:"session_id"`
	StepNum      int                `json:"step_num"`
	UserGoal     string             `json:"user_goal,omitempty"`
	State        *AgentState        `json:"state"`
	History      []analyzer.Message `json:"history"`
	SavedAt      time.Time          `json:"saved_at"`
}

// CheckpointStore checkpoint 持久化
type CheckpointStore struct {
	dir       string
	sessionID string
}

// NewCheckpointStore 创建 checkpoint 存储
func NewCheckpointStore(sessionID string) (*CheckpointStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".deepsentry", "sessions", sessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &CheckpointStore{dir: dir, sessionID: sessionID}, nil
}

// SessionDir 返回会话目录
func (c *CheckpointStore) SessionDir() string {
	return c.dir
}

// Save 保存 checkpoint
func (c *CheckpointStore) Save(data CheckpointData) error {
	data.SessionID = c.sessionID
	data.SavedAt = time.Now()
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.dir, "checkpoint.json.tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.dir, "checkpoint.json"))
}

// Load 加载 checkpoint
func LoadCheckpoint(sessionID string) (*CheckpointData, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".deepsentry", "sessions", sessionID, "checkpoint.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法加载会话 %s: %w", sessionID, err)
	}
	var data CheckpointData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	if data.State == nil {
		data.State = NewAgentState("")
	}
	if data.State.LoadedSkills == nil {
		data.State.LoadedSkills = make(map[string]string)
	}
	if data.State.Memory == nil {
		data.State.Memory = make(map[string]string)
	}
	return &data, nil
}

// ListSessions 列出可恢复的会话 ID
func ListSessions() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(home, ".deepsentry", "sessions")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "checkpoint.json")); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	return ids, nil
}

// SessionSummary 会话摘要（供 TUI 选择器）
type SessionSummary struct {
	ID      string
	StepNum int
	SavedAt time.Time
	Goal    string
}

// ListSessionSummaries 列出可恢复会话及元数据
func ListSessionSummaries() ([]SessionSummary, error) {
	ids, err := ListSessions()
	if err != nil {
		return nil, err
	}
	out := make([]SessionSummary, 0, len(ids))
	for _, id := range ids {
		cp, err := LoadCheckpoint(id)
		if err != nil {
			continue
		}
		out = append(out, SessionSummary{
			ID: id, StepNum: cp.StepNum, SavedAt: cp.SavedAt, Goal: cp.UserGoal,
		})
	}
	return out, nil
}

// NewSessionID 生成新会话 ID
func NewSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}
