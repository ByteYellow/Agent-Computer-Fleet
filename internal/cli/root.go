package cli

import (
	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	var dataDir string
	root := &cobra.Command{
		Use:   "acfctl",
		Short: "Agent Computer Fleet control CLI",
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", store.DefaultDataDir, "local acf data directory")

	root.AddCommand(initCmd(&dataDir))
	root.AddCommand(leaseCmd(&dataDir))
	root.AddCommand(sessionCmd(&dataDir))
	root.AddCommand(execCmd(&dataDir))
	root.AddCommand(processCmd(&dataDir))
	root.AddCommand(portCmd(&dataDir))
	root.AddCommand(runtimeCmd())
	root.AddCommand(templateCmd(&dataDir))
	root.AddCommand(apiCmd(&dataDir))
	root.AddCommand(telemetryCmd(&dataDir))
	root.AddCommand(graphCmd(&dataDir))
	root.AddCommand(forensicsCmd(&dataDir))
	root.AddCommand(baselineCmd(&dataDir))
	root.AddCommand(poolCmd(&dataDir))
	root.AddCommand(egressCmd(&dataDir))
	root.AddCommand(credentialCmd(&dataDir))
	root.AddCommand(nodeCmd(&dataDir))
	root.AddCommand(snapshotCmd(&dataDir))
	root.AddCommand(forkCmd(&dataDir))
	root.AddCommand(attemptCmd(&dataDir))
	root.AddCommand(policyCmd(&dataDir))
	root.AddCommand(costCmd(&dataDir))
	root.AddCommand(benchCmd())
	return root
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
	rt, err := node.NewDockerRuntime()
	if err != nil {
		db.Close()
		return control.Service{}, nil, err
	}
	return control.Service{DB: db, Paths: paths, Runtime: rt}, func() { db.Close() }, nil
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
