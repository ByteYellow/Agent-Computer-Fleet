package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/daemon"
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
	var spoolInterval time.Duration
	var spoolLimit int
	var spoolMaxQueued int
	var spoolMaxBytes int64
	var spoolMaxBatchBytes int64
	var spoolDropPolicy string
	var gcInterval time.Duration
	var gcLimit int
	var authToken string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "run the local AgentProvenance daemon/API server",
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
			server.SpoolInterval = spoolInterval
			server.SpoolLimit = spoolLimit
			server.SpoolMaxQueued = spoolMaxQueued
			server.SpoolMaxBytes = spoolMaxBytes
			server.SpoolMaxBatchBytes = spoolMaxBatchBytes
			server.SpoolDropPolicy = spoolDropPolicy
			server.GCInterval = gcInterval
			server.GCLimit = gcLimit
			if authToken == "" {
				authToken = os.Getenv("AGENTPROV_DAEMON_TOKEN")
			}
			server.AuthToken = authToken
			releaseLock, lockErr := daemon.AcquireLock(*dataDir, listen)
			if lockErr != nil {
				return lockErr
			}
			defer releaseLock()
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			go server.StartSampler(ctx)
			go server.StartSpoolWorker(ctx)
			go server.StartEvidenceWorker(ctx)
			go server.StartGCWorker(ctx)
			fmt.Fprintf(cmd.ErrOrStderr(), "agentprov daemon listening on http://%s sample_interval=%s sample_limit=%d sample_timeout=%s spool_interval=%s evidence_interval=%s gc_interval=%s\n", listen, sampleInterval, sampleLimit, sampleTimeout, spoolInterval, evidenceInterval, gcInterval)
			httpServer := &http.Server{Addr: listen, Handler: server.Handler()}
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpServer.Shutdown(shutdownCtx)
			}()
			err = httpServer.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
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
	serve.Flags().DurationVar(&spoolInterval, "spool-interval", 1*time.Second, "background telemetry spool processing interval; set 0 to disable")
	serve.Flags().IntVar(&spoolLimit, "spool-limit", 100, "maximum queued telemetry spool batches processed per interval")
	serve.Flags().IntVar(&spoolMaxQueued, "spool-max-queued", 1000, "maximum queued telemetry spool batches accepted before backpressure rejects new ingest")
	serve.Flags().Int64Var(&spoolMaxBytes, "spool-max-bytes", 1<<30, "maximum total bytes held by queued/processing telemetry spool batches; set 0 to disable")
	serve.Flags().Int64Var(&spoolMaxBatchBytes, "spool-max-batch-bytes", 256<<20, "maximum bytes accepted in one telemetry spool batch; set 0 to disable")
	serve.Flags().StringVar(&spoolDropPolicy, "spool-drop-policy", "reject", "telemetry spool queue-full behavior: reject or drop_oldest")
	serve.Flags().DurationVar(&gcInterval, "gc-interval", 5*time.Second, "background async GC interval; set 0 to disable")
	serve.Flags().IntVar(&gcLimit, "gc-limit", 100, "maximum queued GC jobs processed per interval")
	serve.Flags().StringVar(&authToken, "auth-token", "", "require this bearer token on all API routes except GET /v1/health (also AGENTPROV_DAEMON_TOKEN); empty = open")
	cmd := &cobra.Command{Use: "daemon", Short: "local daemon/API server commands"}
	cmd.AddCommand(serve)
	return cmd
}
