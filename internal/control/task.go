package control

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Task struct {
	RunID          string   `yaml:"run_id"`
	Image          string   `yaml:"image"`
	Workspace      string   `yaml:"workspace"`
	Command        []string `yaml:"command"`
	RiskTier       string   `yaml:"risk_tier"`
	NetworkMode    string   `yaml:"network_mode"`
	CPURequest     float64  `yaml:"cpu_request"`
	MemoryMB       int64    `yaml:"memory_mb"`
	TimeoutSeconds int      `yaml:"timeout_seconds"`
}

func LoadTask(path string) (Task, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Task{}, nil, err
	}
	task, err := ParseTask(raw)
	if err != nil {
		return Task{}, nil, err
	}
	return task, raw, nil
}

func ParseTask(raw []byte) (Task, error) {
	var task Task
	if err := yaml.Unmarshal(raw, &task); err != nil {
		return Task{}, err
	}
	if task.RiskTier == "" {
		task.RiskTier = "medium"
	}
	if task.NetworkMode == "" {
		task.NetworkMode = "allowlist"
	}
	if task.Workspace == "" {
		task.Workspace = "/workspace"
	}
	return task, nil
}
