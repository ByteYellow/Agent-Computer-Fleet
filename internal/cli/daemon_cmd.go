package cli

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/daemon"
	"github.com/spf13/cobra"
)

func daemonCmd(dataDir *string) *cobra.Command {
	var listen string
	var sampleInterval time.Duration
	var sampleLimit int
	var sampleTimeout time.Duration
	var rawRetention time.Duration
	var maxRawSamples int
	var evidenceInterval time.Duration
	var evidenceLimit int
	var gcInterval time.Duration
	var gcLimit int
	serve := &cobra.Command{
		Use:   "serve",
		Short: "run the local Agent Computer daemon/API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			server, closeFn, err := daemon.NewServer(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			server.SampleInterval = sampleInterval
			server.SampleLimit = sampleLimit
			server.SampleTimeout = sampleTimeout
			server.RawRetention = rawRetention
			server.MaxRawSamples = maxRawSamples
			server.EvidenceInterval = evidenceInterval
			server.EvidenceLimit = evidenceLimit
			server.GCInterval = gcInterval
			server.GCLimit = gcLimit
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			go server.StartSampler(ctx)
			go server.StartEvidenceWorker(ctx)
			go server.StartGCWorker(ctx)
			fmt.Fprintf(cmd.ErrOrStderr(), "acf daemon listening on http://%s sample_interval=%s sample_limit=%d sample_timeout=%s evidence_interval=%s gc_interval=%s\n", listen, sampleInterval, sampleLimit, sampleTimeout, evidenceInterval, gcInterval)
			return http.ListenAndServe(listen, server.Handler())
		},
	}
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:8574", "daemon listen address")
	serve.Flags().DurationVar(&sampleInterval, "sample-interval", 5*time.Second, "background Docker stats sampling interval; set 0 to disable")
	serve.Flags().IntVar(&sampleLimit, "sample-limit", 64, "maximum running sessions sampled per interval")
	serve.Flags().DurationVar(&sampleTimeout, "sample-timeout", 2*time.Second, "timeout for each Docker stats sample")
	serve.Flags().DurationVar(&rawRetention, "raw-retention", 10*time.Minute, "raw cpu sample retention duration")
	serve.Flags().IntVar(&maxRawSamples, "max-raw-samples", 512, "maximum retained raw cpu samples per session")
	serve.Flags().DurationVar(&evidenceInterval, "evidence-interval", 2*time.Second, "background evidence materialization interval; set 0 to disable")
	serve.Flags().IntVar(&evidenceLimit, "evidence-limit", 100, "maximum queued evidence events processed per interval")
	serve.Flags().DurationVar(&gcInterval, "gc-interval", 5*time.Second, "background async GC interval; set 0 to disable")
	serve.Flags().IntVar(&gcLimit, "gc-limit", 100, "maximum queued GC jobs processed per interval")
	cmd := &cobra.Command{Use: "daemon", Short: "local daemon/API server commands"}
	cmd.AddCommand(serve)
	return cmd
}
