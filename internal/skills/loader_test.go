package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalogExpandsHomeSkillSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	skillDir := filepath.Join(home, ".deepsentry", "skills", "external-audit")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir skill dir: %v", err)
	}
	content := `---
name: external-audit
description: 外部审计 Skill
license: Apache-2.0
---

# External Audit
`
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write skill: %v", err)
	}

	catalog, err := LoadCatalog([]string{"~/.deepsentry/skills"})
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	meta, ok := catalog.FindSkill("external-audit")
	if !ok {
		t.Fatalf("expected external-audit skill, got %#v", catalog.Skills)
	}
	if meta.Description != "外部审计 Skill" {
		t.Fatalf("unexpected description: %q", meta.Description)
	}
}
