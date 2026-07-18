package harness

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/security"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"
)

// CheckpointData 会话 checkpoint 快照
type CheckpointData struct {
	SessionID string             `json:"session_id"`
	StepNum   int                `json:"step_num"`
	UserGoal  string             `json:"user_goal,omitempty"`
	State     *AgentState        `json:"state"`
	History   []analyzer.Message `json:"history"`
	SavedAt   time.Time          `json:"saved_at"`
}

// CheckpointStore checkpoint 持久化
type CheckpointStore struct {
	dir       string
	sessionID string
}

var sessionIDPattern = regexp.MustCompile(`^session_[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validateSessionID(sessionID string) error {
	if !sessionIDPattern.MatchString(sessionID) {
		return fmt.Errorf("非法 session_id: %q", sessionID)
	}
	return nil
}

// NewCheckpointStore 创建 checkpoint 存储
func NewCheckpointStore(sessionID string) (*CheckpointStore, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".deepsentry", "sessions", sessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
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
	raw, err := security.RedactJSON(data)
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(c.dir, "checkpoint-*.tmp")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(raw); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return replaceCheckpointFile(tmp, filepath.Join(c.dir, "checkpoint.json"))
}

func replaceCheckpointFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows cannot atomically replace an existing destination with Rename.
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}

// Load 加载 checkpoint
func LoadCheckpoint(sessionID string) (*CheckpointData, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
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
	if data.State.CoreClues == nil {
		data.State.CoreClues = []CoreClue{}
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
		if e.IsDir() && validateSessionID(e.Name()) == nil {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "checkpoint.json")); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].SavedAt.Equal(out[j].SavedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].SavedAt.After(out[j].SavedAt)
	})
	return out, nil
}

// NewSessionID 生成新会话 ID
func NewSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}
