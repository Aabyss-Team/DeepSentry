package skills

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadCatalogHonorsClaudeAndCodexInvocationPolicies(t *testing.T) {
	root := t.TempDir()
	writeSkill := func(dir, frontmatter, openAI string) {
		t.Helper()
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(filepath.Join(path, "agents"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("---\n"+frontmatter+"---\n# Body\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if openAI != "" {
			if err := os.WriteFile(filepath.Join(path, "agents", "openai.yaml"), []byte(openAI), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeSkill("explicit", "name: explicit\ndescription: Explicit only\ndisable-model-invocation: true\n", "")
	writeSkill("model-only", "name: model-only\ndescription: Model only\nuser-invocable: false\n", "")
	writeSkill("codex-policy", "name: codex-policy\ndescription: Codex policy\n", "policy:\n  allow_implicit_invocation: false\n")

	catalog, err := LoadCatalog([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	explicit, ok := catalog.FindSkill("EXPLICIT")
	if !ok || explicit.AllowImplicit || !explicit.UserInvocable {
		t.Fatalf("unexpected explicit metadata: %#v", explicit)
	}
	modelOnly, ok := catalog.FindSkill("model-only")
	if !ok || !modelOnly.AllowImplicit || modelOnly.UserInvocable {
		t.Fatalf("unexpected model-only metadata: %#v", modelOnly)
	}
	codex, ok := catalog.FindSkill("codex-policy")
	if !ok || codex.AllowImplicit || codex.InvocationSource != "agents/openai.yaml" {
		t.Fatalf("unexpected Codex policy metadata: %#v", codex)
	}
	prompt := catalog.FormatCatalogPrompt()
	if strings.Contains(prompt, "**explicit**") || strings.Contains(prompt, "**codex-policy**") || !strings.Contains(prompt, "**model-only**") {
		t.Fatalf("invocation policy not reflected in catalog prompt:\n%s", prompt)
	}
}

func TestFormatCatalogPromptHasBoundedProgressiveDisclosure(t *testing.T) {
	catalog := &SkillCatalog{}
	for i := 0; i < 200; i++ {
		catalog.Skills = append(catalog.Skills, SkillMeta{Name: "skill-" + strings.Repeat("x", 20), Description: strings.Repeat("detail ", 40), AllowImplicit: true})
	}
	prompt := catalog.FormatCatalogPrompt()
	if len(prompt) > 8500 {
		t.Fatalf("catalog prompt exceeded budget: %d bytes", len(prompt))
	}
	if !strings.Contains(prompt, "因目录预算未列出") {
		t.Fatalf("expected progressive disclosure notice:\n%s", prompt)
	}
}

func TestLoadCatalogRejectsMalformedSkillMetadata(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "bad")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Missing frontmatter"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 0 {
		t.Fatalf("malformed Skill should be skipped: %#v", catalog.Skills)
	}
}

func TestResolveSourcesAlwaysIncludesManagedRootAndHonorsDisable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	custom := filepath.Join(home, "custom-skills")
	managed := filepath.Join(home, ".deepsentry", "skills")
	sources := ResolveSources([]string{custom, custom}, nil)
	if len(sources) != 2 || sources[0] != custom || sources[1] != managed {
		t.Fatalf("resolved sources=%#v", sources)
	}
	sources = ResolveSources([]string{custom}, []string{managed})
	if len(sources) != 1 || sources[0] != custom {
		t.Fatalf("disabled managed root should be absent: %#v", sources)
	}
}

func TestCatalogReloadDiscoversNewlyLandedSkill(t *testing.T) {
	root := t.TempDir()
	catalog, err := LoadCatalog([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 0 {
		t.Fatalf("unexpected initial skills: %#v", catalog.Skills)
	}
	dir := filepath.Join(root, "hot-skill")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: hot-skill\ndescription: Hot reload test\n---\n# Hot\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.FindSkill("hot-skill"); !ok {
		t.Fatalf("reloaded catalog=%#v", catalog.Skills)
	}
}

func TestCatalogDisabledSkillPolicySurvivesReloadAndCanBeEnabled(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"alpha", "beta"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := "---\nname: " + name + "\ndescription: " + name + " skill\n---\n# Body\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := LoadCatalog([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	catalog.ApplyDisabledSkills([]string{"ALPHA", "alpha"})
	if !catalog.IsDisabled("Alpha") {
		t.Fatal("disabled name should be matched case-insensitively")
	}
	if _, ok := catalog.FindSkill("alpha"); ok {
		t.Fatal("disabled skill remained discoverable")
	}
	if _, ok := catalog.FindSkill("beta"); !ok {
		t.Fatal("unrelated skill was filtered")
	}
	if prompt := catalog.FormatCatalogPrompt(); strings.Contains(prompt, "**alpha**") {
		t.Fatalf("disabled skill leaked into model prompt:\n%s", prompt)
	}
	if err := catalog.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.FindSkill("alpha"); ok {
		t.Fatal("reload forgot disabled policy")
	}
	if err := catalog.ReloadWithDisabled([]string{"*"}); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 0 || !catalog.IsDisabled("beta") {
		t.Fatalf("global disable sentinel did not block every Skill: %#v", catalog.Skills)
	}
	if err := catalog.ReloadWithDisabled(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.FindSkill("alpha"); !ok {
		t.Fatal("enabled skill was not rediscovered without restart")
	}
}
