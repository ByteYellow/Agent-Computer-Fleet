package cli

import (
	"fmt"
	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/store"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/substrate/runtime"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func NewRootCommand() *cobra.Command {
	var dataDir string
	var daemonURL string
	root := &cobra.Command{
		Use:   "agentprov",
		Short: "AgentProvenance control CLI",
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", store.DefaultDataDir, "local AgentProvenance data directory")
	root.PersistentFlags().StringVar(&daemonURL, "daemon-url", firstEnv("AGENTPROV_DAEMON_URL"), "local daemon URL; also read from AGENTPROV_DAEMON_URL")

	root.AddCommand(launchCmd(&dataDir))
	root.AddCommand(doctorCmd(&dataDir))
	root.AddCommand(internalCmd())
	root.AddCommand(intentCmd(&dataDir))
	root.AddCommand(initCmd(&dataDir))
	root.AddCommand(daemonCmd(&dataDir))
	root.AddCommand(leaseCmd(&dataDir, &daemonURL))
	root.AddCommand(sessionCmd(&dataDir, &daemonURL))
	root.AddCommand(execCmd(&dataDir, &daemonURL))
	root.AddCommand(processCmd(&dataDir))
	root.AddCommand(portCmd(&dataDir))
	root.AddCommand(adapterCmd())
	root.AddCommand(runtimeCmd(&dataDir))
	root.AddCommand(templateCmd(&dataDir))
	root.AddCommand(apiCmd(&dataDir))
	root.AddCommand(recordCmd(&dataDir))
	root.AddCommand(sensorCmd(&dataDir))
	root.AddCommand(observeCmd(&dataDir, &daemonURL))
	root.AddCommand(telemetryCmd(&dataDir, &daemonURL))
	root.AddCommand(timelineCmd(&dataDir, &daemonURL))
	root.AddCommand(effectCmd(&dataDir))
	root.AddCommand(graphCmd(&dataDir, &daemonURL))
	root.AddCommand(forensicsCmd(&dataDir, &daemonURL))
	root.AddCommand(evidenceCmd(&dataDir, &daemonURL))
	root.AddCommand(securityCmd(&dataDir, &daemonURL))
	root.AddCommand(signalCmd(&dataDir, &daemonURL))
	root.AddCommand(signalsCmd(&dataDir))
	root.AddCommand(aiCmd(&dataDir))
	root.AddCommand(hooksCmd(&dataDir))
	root.AddCommand(dashboardCmd(&dataDir))
	root.AddCommand(complianceCmd(&dataDir))
	root.AddCommand(gcCmd(&dataDir))
	root.AddCommand(baselineCmd(&dataDir))
	root.AddCommand(snapshotCmd(&dataDir, &daemonURL))
	root.AddCommand(forkCmd(&dataDir))
	root.AddCommand(policyCmd(&dataDir))
	root.AddCommand(costCmd(&dataDir))
	return root
}

func daemonClient(daemonURL string) (daemon.Client, bool) {
	if daemonURL == "" {
		return daemon.Client{}, false
	}
	return daemon.NewClient(daemonURL), true
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func controlSvc(dataDir string) (control.Service, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return control.Service{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return control.Service{}, nil, err
	}
	driver, err := runtimeplane.NewDriver("docker", paths)
	if err != nil {
		db.Close()
		return control.Service{}, nil, err
	}
	return control.Service{DB: db, Paths: paths, Driver: driver}, func() { db.Close() }, nil
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func wallSecondsText(startedAt, endedAt string) string {
	if startedAt == "" || endedAt == "" {
		return ""
	}
	start, err := time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return ""
	}
	end, err := time.Parse(time.RFC3339Nano, endedAt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.3f", end.Sub(start).Seconds())
}
