package scheduler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Store struct {
	Path string
	mu   sync.Mutex
}

var storeFileMu sync.Mutex

func NewStore(path string) *Store {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultStorePath
	}
	return &Store{Path: path}
}

func (s *Store) Load() ([]Task, error) {
	storeFileMu.Lock()
	defer storeFileMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadUnlocked()
}

func (s *Store) Save(tasks []Task) error {
	storeFileMu.Lock()
	defer storeFileMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveUnlocked(tasks)
}

func (s *Store) Add(task Task) error {
	_, created, err := s.AddUnique(task)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("等价定时任务已存在")
	}
	return nil
}

// AddUnique makes schedule creation idempotent. Re-submitting the same prompt
// and schedule returns the existing task instead of writing another job.
func (s *Store) AddUnique(task Task) (existing Task, created bool, err error) {
	storeFileMu.Lock()
	defer storeFileMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	tasks, err := s.loadUnlocked()
	if err != nil {
		return Task{}, false, err
	}
	for _, existing := range tasks {
		if existing.ID == task.ID {
			return existing, false, nil
		}
		if equivalentTask(existing, task) {
			return existing, false, nil
		}
	}
	tasks = append(tasks, task)
	if err := s.saveUnlocked(tasks); err != nil {
		return Task{}, false, err
	}
	return task, true, nil
}

func equivalentTask(a, b Task) bool {
	normalize := func(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }
	return normalize(a.Prompt) == normalize(b.Prompt) &&
		a.Kind == b.Kind && a.RunAt.Equal(b.RunAt) && a.Timezone == b.Timezone &&
		a.Repeat == b.Repeat && a.Weekday == b.Weekday && a.IntervalSec == b.IntervalSec &&
		normalize(a.Selector) == normalize(b.Selector) && normalize(a.Notify) == normalize(b.Notify) &&
		a.AllowBatch == b.AllowBatch
}

func (s *Store) Remove(id string) (Task, bool, error) {
	storeFileMu.Lock()
	defer storeFileMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	tasks, err := s.loadUnlocked()
	if err != nil {
		return Task{}, false, err
	}
	var removed Task
	kept := tasks[:0]
	found := false
	for _, task := range tasks {
		if task.ID == id {
			removed = task
			found = true
			continue
		}
		kept = append(kept, task)
	}
	if !found {
		return Task{}, false, nil
	}
	return removed, true, s.saveUnlocked(kept)
}

func (s *Store) Update(task Task) error {
	storeFileMu.Lock()
	defer storeFileMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	tasks, err := s.loadUnlocked()
	if err != nil {
		return err
	}
	for i := range tasks {
		if tasks[i].ID == task.ID {
			tasks[i] = task
			return s.saveUnlocked(tasks)
		}
	}
	return fmt.Errorf("未找到任务: %s", task.ID)
}

func (s *Store) Due(now time.Time) ([]Task, error) {
	tasks, err := s.Load()
	if err != nil {
		return nil, err
	}
	var due []Task
	for _, task := range tasks {
		if task.Status != StatusEnabled {
			continue
		}
		if !task.RunAt.After(now) {
			due = append(due, task)
		}
	}
	sortTasks(due)
	return due, nil
}

func (s *Store) loadUnlocked() ([]Task, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var tasks []Task
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, fmt.Errorf("读取定时任务失败: %w", err)
	}
	sortTasks(tasks)
	return tasks, nil
}

func (s *Store) saveUnlocked(tasks []Task) error {
	sortTasks(tasks)
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(s.Path), 0o700)
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.Path), "tasks-*.tmp")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(append(data, '\n')); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.Path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func sortTasks(tasks []Task) {
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].RunAt.Equal(tasks[j].RunAt) {
			return tasks[i].ID < tasks[j].ID
		}
		return tasks[i].RunAt.Before(tasks[j].RunAt)
	})
}
