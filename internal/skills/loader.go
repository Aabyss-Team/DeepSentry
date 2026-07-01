package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SkillMeta Skill 元数据（对标 deepagents SkillsMiddleware 的 SkillMetadata）
type SkillMeta struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	License     string `yaml:"license,omitempty"`
	Path        string // SKILL.md 绝对路径
	Dir         string // skill 目录
}

// SkillCatalog Skill 目录索引（渐进式披露：仅元数据注入 prompt）
type SkillCatalog struct {
	Skills []SkillMeta
}

// LoadCatalog 从多个来源路径加载 Skill 目录
// sources 按优先级排列，后加载的同名 skill 覆盖先加载的
func LoadCatalog(sources []string) (*SkillCatalog, error) {
	catalog := &SkillCatalog{}
	seen := make(map[string]int)

	for _, src := range sources {
		if src == "" {
			continue
		}
		src = expandSourcePath(src)
		entries, err := os.ReadDir(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("读取 skill 目录 %s 失败: %w", src, err)
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			skillDir := filepath.Join(src, entry.Name())
			skillFile := filepath.Join(skillDir, "SKILL.md")
			if _, err := os.Stat(skillFile); err != nil {
				continue
			}

			meta, err := parseSkillMeta(skillFile, skillDir)
			if err != nil {
				continue
			}

			if idx, exists := seen[meta.Name]; exists {
				catalog.Skills[idx] = meta
			} else {
				seen[meta.Name] = len(catalog.Skills)
				catalog.Skills = append(catalog.Skills, meta)
			}
		}
	}

	return catalog, nil
}

// LoadSkillContent 加载完整 Skill 内容（按需披露）
func LoadSkillContent(meta SkillMeta) (string, error) {
	data, err := os.ReadFile(meta.Path)
	if err != nil {
		return "", fmt.Errorf("读取 skill %s 失败: %w", meta.Name, err)
	}
	return string(data), nil
}

// FindSkill 按名称查找 Skill
func (c *SkillCatalog) FindSkill(name string) (*SkillMeta, bool) {
	for i := range c.Skills {
		if c.Skills[i].Name == name {
			return &c.Skills[i], true
		}
	}
	return nil, false
}

// FormatCatalogPrompt 生成 Skill 目录 prompt 片段
func (c *SkillCatalog) FormatCatalogPrompt() string {
	if len(c.Skills) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n【可用 Skills — 按需加载】\n")
	b.WriteString("使用 action=\"load_skill\" + skill_name 加载完整指令。仅在需要时加载，避免浪费上下文。\n\n")
	for _, s := range c.Skills {
		b.WriteString(fmt.Sprintf("- **%s**: %s\n", s.Name, s.Description))
	}
	return b.String()
}

func parseSkillMeta(skillFile, skillDir string) (SkillMeta, error) {
	data, err := os.ReadFile(skillFile)
	if err != nil {
		return SkillMeta{}, err
	}

	content := string(data)
	meta := SkillMeta{
		Path: skillFile,
		Dir:  skillDir,
	}

	// 解析 YAML frontmatter
	if strings.HasPrefix(content, "---") {
		parts := strings.SplitN(content, "---", 3)
		if len(parts) >= 3 {
			if err := yaml.Unmarshal([]byte(parts[1]), &meta); err != nil {
				return SkillMeta{}, err
			}
		}
	}

	if meta.Name == "" {
		meta.Name = filepath.Base(skillDir)
	}
	if meta.Description == "" {
		meta.Description = "安全排查技能"
	}

	return meta, nil
}

func expandSourcePath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// DefaultSources 返回默认 Skill 来源路径
func DefaultSources() []string {
	sources := []string{"skills"}
	if home, err := os.UserHomeDir(); err == nil {
		sources = append(sources, filepath.Join(home, ".deepsentry", "skills"))
	}
	return sources
}
