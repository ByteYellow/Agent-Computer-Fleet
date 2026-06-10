package node

type CreateSessionRequest struct {
	SessionID         string
	LeaseID           string
	RunID             string
	Image             string
	WorkspaceHostPath string
	MemoryMB          int64
	CPURequest        float64
	NetworkMode       string
}

type Runtime interface {
	CreateSession(req CreateSessionRequest) (containerID string, err error)
	Exec(containerID string, command []string, stream bool) (ExecResult, error)
	Interrupt(containerID string) error
	Stop(containerID string) error
	Remove(containerID string) error
}

type ExecResult struct {
	ExecID   string
	ExitCode int
}
