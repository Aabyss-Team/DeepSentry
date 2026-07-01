package scheduler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Store struct {
	Path string
	mu   sync.Mutex
}

func NewStore(path string) *Store {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultStorePath
	}
	return &Store{Path: path}
}

func (s *Store) Load() ([]Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadUnlocked()
}

func (s *Store) Save(tasks []Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveUnlocked(tasks)
}

func (s *Store) Add(task Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tasks, err := s.loadUnlocked()
	if err != nil {
		return err
	}
	for _, existing := range tasks {
		if existing.ID == task.ID {
			return fmt.Errorf("任务 ID 已存在: %s", task.ID)
		}
	}
	tasks = append(tasks, task)
	return s.saveUnlocked(tasks)
}

func (s *Store) Remove(id string) (Task, bool, error) {
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
	if err := os.MkdirAll(filepath.Dir(s.Path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
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
