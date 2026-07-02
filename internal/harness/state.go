package harness

// AgentState 持久化 Agent 运行时状态（对标 DeepAgentState）
type AgentState struct {
	Todos        []TodoItem
	LoadedSkills map[string]string // skill name -> full content
	Memory       map[string]string // 会话内临时 KV（不落盘）
	WorkspaceDir string            // 工具输出卸载目录
	SessionID    string            // checkpoint/session id，用于隔离输出卸载文件
}

// NewAgentState 创建初始状态
func NewAgentState(workspaceDir string) *AgentState {
	return NewAgentStateWithSession(workspaceDir, "")
}

func NewAgentStateWithSession(workspaceDir, sessionID string) *AgentState {
	return &AgentState{
		Todos:        []TodoItem{},
		LoadedSkills: make(map[string]string),
		Memory:       make(map[string]string),
		WorkspaceDir: workspaceDir,
		SessionID:    sessionID,
	}
}

// SetMemory 写入记忆
func (s *AgentState) SetMemory(key, value string) {
	s.Memory[key] = value
}

// GetMemory 读取记忆
func (s *AgentState) GetMemory(key string) (string, bool) {
	v, ok := s.Memory[key]
	return v, ok
}
