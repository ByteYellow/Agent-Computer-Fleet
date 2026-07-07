package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func graphCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var artifactRef string
	var attemptID string
	var toolCallID string
	var processID string
	openDB := func() (*sql.DB, error) {
		paths, err := store.Init(*dataDir)
		if err != nil {
			return nil, err
		}
		db, err := store.Open(paths)
		if err != nil {
			return nil, err
		}
		return db, nil
	}
	trace := &cobra.Command{
		Use:   "trace",
		Short: "trace run or artifact provenance",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			selected := 0
			for _, value := range []string{runID, artifactRef, attemptID, toolCallID, processID} {
				if value != "" {
					selected++
				}
			}
			if selected > 1 {
				return fmt.Errorf("use only one of --run, --artifact, --execution-scope/--attempt, --tool-call, or --process")
			}
			if processID != "" {
				return provenance.TraceProcess(db, processID, cmd.OutOrStdout())
			}
			if toolCallID != "" {
				return provenance.TraceToolCall(db, toolCallID, cmd.OutOrStdout())
			}
			if attemptID != "" {
				return provenance.TraceAttempt(db, attemptID, cmd.OutOrStdout())
			}
			if artifactRef != "" {
				return provenance.TraceArtifact(db, artifactRef, cmd.OutOrStdout())
			}
			if runID != "" {
				return provenance.TraceRun(db, runID, cmd.OutOrStdout())
			}
			return fmt.Errorf("one of --run, --artifact, --execution-scope/--attempt, --tool-call, or --process is required")
		},
	}
	trace.Flags().StringVar(&runID, "run", "", "run id")
	trace.Flags().StringVar(&artifactRef, "artifact", "", "artifact result ref")
	trace.Flags().StringVar(&attemptID, "execution-scope", "", "execution scope id")
	trace.Flags().StringVar(&attemptID, "attempt", "", "legacy alias for --execution-scope")
	trace.Flags().StringVar(&toolCallID, "tool-call", "", "tool call id")
	trace.Flags().StringVar(&processID, "process", "", "process id")
	_ = trace.Flags().MarkHidden("attempt")

	var refsRunID string
	refs := &cobra.Command{
		Use:   "refs",
		Short: "list Git-like provenance refs for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if refsRunID == "" {
				return fmt.Errorf("--run is required")
			}
			return provenance.Refs(db, refsRunID, cmd.OutOrStdout())
		},
	}
	refs.Flags().StringVar(&refsRunID, "run", "", "run id")

	var logRunID string
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "show Git-like provenance timeline for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if logRunID == "" {
				return fmt.Errorf("--run is required")
			}
			return provenance.Log(db, logRunID, cmd.OutOrStdout())
		},
	}
	logCmd.Flags().StringVar(&logRunID, "run", "", "run id")

	var materializeRunID string
	materialize := &cobra.Command{
		Use:   "materialize",
		Short: "materialize a run into content-addressed provenance objects",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			if materializeRunID == "" {
				return fmt.Errorf("--run is required")
			}
			result, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun(materializeRunID)
			if err != nil {
				return err
			}
			provenance.PrintMaterializeResult(cmd.OutOrStdout(), result)
			return nil
		},
	}
	materialize.Flags().StringVar(&materializeRunID, "run", "", "run id")

	var llmRunID string
	materializeLLM := &cobra.Command{
		Use:   "materialize-llm",
		Short: "objectify captured LLM request/response bodies + build llm_call nodes for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			if llmRunID == "" {
				return fmt.Errorf("--run is required")
			}
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			n, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, llmRunID)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
				"schema_version": "agentprovenance.materialize_llm/v1",
				"run":            llmRunID,
				"llm_calls":      n,
			})
		},
	}
	materializeLLM.Flags().StringVar(&llmRunID, "run", "", "run id")

	var objectsRunID string
	var objectsLimit int
	var objectsCursor string
	var objectsJSON bool
	objectsCmd := &cobra.Command{
		Use:   "objects",
		Short: "list content-addressed provenance objects for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if objectsRunID == "" {
				return fmt.Errorf("--run is required")
			}
			opts := provenance.ObjectListOptions{RunID: objectsRunID, Limit: objectsLimit, Cursor: objectsCursor}
			if objectsJSON {
				return provenance.ObjectsPageJSON(db, opts, cmd.OutOrStdout())
			}
			return provenance.ObjectsPage(db, opts, cmd.OutOrStdout())
		},
	}
	objectsCmd.Flags().StringVar(&objectsRunID, "run", "", "run id")
	objectsCmd.Flags().IntVar(&objectsLimit, "limit", 100, "maximum provenance objects returned")
	objectsCmd.Flags().StringVar(&objectsCursor, "cursor", "", "pagination cursor from previous graph objects output")
	objectsCmd.Flags().BoolVar(&objectsJSON, "json", false, "emit structured provenance object refs JSON")

	var diffRunID string
	var diffFile string
	var diffJSON bool
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "diff a workspace file across execution scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if diffJSON {
				return provenance.DiffFileJSON(db, diffRunID, diffFile, cmd.OutOrStdout())
			}
			return provenance.DiffFile(db, diffRunID, diffFile, cmd.OutOrStdout())
		},
	}
	diffCmd.Flags().StringVar(&diffRunID, "run", "", "run id")
	diffCmd.Flags().StringVar(&diffFile, "file", "", "workspace-relative file path")
	diffCmd.Flags().BoolVar(&diffJSON, "json", false, "emit structured file diff JSON")

	var blameRunID string
	var blameFile string
	var blameJSON bool
	blameCmd := &cobra.Command{
		Use:   "blame",
		Short: "attribute a workspace file to execution scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if blameJSON {
				return provenance.BlameFileJSON(db, blameRunID, blameFile, cmd.OutOrStdout())
			}
			return provenance.BlameFile(db, blameRunID, blameFile, cmd.OutOrStdout())
		},
	}
	blameCmd.Flags().StringVar(&blameRunID, "run", "", "run id")
	blameCmd.Flags().StringVar(&blameFile, "file", "", "workspace-relative file path")
	blameCmd.Flags().BoolVar(&blameJSON, "json", false, "emit structured file blame JSON")

	var verifyRunID string
	var verifyJSON bool
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "verify provenance graph references, taint barriers, and object hashes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if verifyRunID == "" {
				return fmt.Errorf("--run is required")
			}
			if client, ok := daemonClient(*daemonURL); ok {
				result, err := client.VerifyGraph(verifyRunID)
				if err != nil {
					return err
				}
				if verifyJSON {
					if err := provenance.PrintVerifyResultJSON(cmd.OutOrStdout(), result); err != nil {
						return err
					}
				} else {
					provenance.PrintVerifyResult(cmd.OutOrStdout(), result)
				}
				if result.ErrorCount > 0 {
					return fmt.Errorf("graph verify failed: errors=%d warnings=%d", result.ErrorCount, result.WarningCount)
				}
				return nil
			}
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if verifyJSON {
				return provenance.VerifyRunJSON(db, verifyRunID, cmd.OutOrStdout())
			}
			return provenance.VerifyRun(db, verifyRunID, cmd.OutOrStdout())
		},
	}
	verifyCmd.Flags().StringVar(&verifyRunID, "run", "", "run id")
	verifyCmd.Flags().BoolVar(&verifyJSON, "json", false, "emit structured graph verification JSON")

	var replayRunID string
	var replayAttemptID string
	var replayJSON bool
	replayCmd := &cobra.Command{
		Use:   "replay",
		Short: "emit a replay plan for a run or execution scope without executing it",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if replayRunID != "" && replayAttemptID != "" {
				return fmt.Errorf("use only one of --run or --execution-scope/--attempt")
			}
			if replayAttemptID != "" {
				if replayJSON {
					return provenance.ReplayAttemptJSON(db, replayAttemptID, cmd.OutOrStdout())
				}
				return provenance.ReplayAttempt(db, replayAttemptID, cmd.OutOrStdout())
			}
			if replayRunID != "" {
				if replayJSON {
					return provenance.ReplayRunJSON(db, replayRunID, cmd.OutOrStdout())
				}
				return provenance.ReplayRun(db, replayRunID, cmd.OutOrStdout())
			}
			return fmt.Errorf("one of --run or --execution-scope/--attempt is required")
		},
	}
	replayCmd.Flags().StringVar(&replayRunID, "run", "", "run id")
	replayCmd.Flags().StringVar(&replayAttemptID, "execution-scope", "", "execution scope id")
	replayCmd.Flags().StringVar(&replayAttemptID, "attempt", "", "legacy alias for --execution-scope")
	replayCmd.Flags().BoolVar(&replayJSON, "json", false, "emit structured replay manifest JSON")
	_ = replayCmd.Flags().MarkHidden("attempt")

	var trajectoriesRunID string
	var trajectoriesJSON bool
	trajectoriesCmd := &cobra.Command{
		Use:   "trajectories",
		Short: "emit per-execution-scope trajectory evidence for external evaluators",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if trajectoriesRunID == "" {
				return fmt.Errorf("--run is required")
			}
			if trajectoriesJSON {
				return provenance.TrajectoriesRunJSON(db, trajectoriesRunID, cmd.OutOrStdout())
			}
			return provenance.TrajectoriesRun(db, trajectoriesRunID, cmd.OutOrStdout())
		},
	}
	trajectoriesCmd.Flags().StringVar(&trajectoriesRunID, "run", "", "run id")
	trajectoriesCmd.Flags().BoolVar(&trajectoriesJSON, "json", false, "emit structured trajectory evidence JSON")

	var lensRunID string
	var lensName string
	var lensFocus string
	var lensOverlays []string
	var lensLimit int
	var lensDetail string
	var lensJSON bool
	lensCmd := &cobra.Command{
		Use:   "lens",
		Short: "project the provenance graph through a graph explorer lens",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := provenance.GraphLensOptions{
				RunID:    lensRunID,
				Lens:     lensName,
				Focus:    lensFocus,
				Overlays: lensOverlays,
				Limit:    lensLimit,
				Detail:   lensDetail,
			}
			if client, ok := daemonClient(*daemonURL); ok {
				manifest, err := client.GraphLens(opts)
				if err != nil {
					return err
				}
				if lensJSON {
					return provenance.PrintGraphLensManifestJSON(cmd.OutOrStdout(), manifest)
				}
				return provenance.PrintGraphLensManifest(cmd.OutOrStdout(), manifest)
			}
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if lensJSON {
				return provenance.GraphLensJSON(db, opts, cmd.OutOrStdout())
			}
			return provenance.GraphLens(db, opts, cmd.OutOrStdout())
		},
	}
	lensCmd.Flags().StringVar(&lensRunID, "run", "", "run id")
	lensCmd.Flags().StringVar(&lensName, "lens", "default", "graph lens: default, security, process, file-artifact, network-egress, data-flow-taint, agent-intent, orchestration, trust-origin, sandbox-boundary")
	lensCmd.Flags().StringVar(&lensFocus, "focus", "", "focus node id to keep selected across lenses")
	lensCmd.Flags().StringVar(&lensDetail, "detail", "summary", "graph detail level: summary, expanded, raw")
	lensCmd.Flags().StringArrayVar(&lensOverlays, "overlay", nil, "overlay annotations to add, repeatable or comma-separated: risk, trust, security")
	lensCmd.Flags().IntVar(&lensLimit, "limit", 500, "maximum graph edges returned")
	lensCmd.Flags().BoolVar(&lensJSON, "json", false, "emit structured graph lens JSON")

	var explainRunID string
	var explainArtifact string
	var explainAttempt string
	var explainToolCall string
	var explainProcess string
	var explainEvent string
	var explainRisk string
	var explainFile string
	var explainDepth int
	var explainLimit int
	var explainCursor string
	var explainJSON bool
	explainCmd := &cobra.Command{
		Use:   "explain",
		Short: "explain runtime causality and provenance for a graph target",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := provenance.ExplainOptions{
				RunID:    explainRunID,
				Artifact: explainArtifact,
				Attempt:  explainAttempt,
				ToolCall: explainToolCall,
				Process:  explainProcess,
				Event:    explainEvent,
				Risk:     explainRisk,
				File:     explainFile,
				Depth:    explainDepth,
				Limit:    explainLimit,
				Cursor:   explainCursor,
				WithJSON: explainJSON,
			}
			if client, ok := daemonClient(*daemonURL); ok {
				manifest, err := client.ExplainGraph(opts)
				if err != nil {
					return err
				}
				if explainJSON {
					return provenance.PrintExplainManifestJSON(cmd.OutOrStdout(), manifest)
				}
				return provenance.PrintExplainManifest(cmd.OutOrStdout(), manifest)
			}
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			return provenance.Explain(db, opts, cmd.OutOrStdout())
		},
	}
	explainCmd.Flags().StringVar(&explainRunID, "run", "", "run id")
	explainCmd.Flags().StringVar(&explainArtifact, "artifact", "", "artifact result ref")
	explainCmd.Flags().StringVar(&explainAttempt, "execution-scope", "", "execution scope id")
	explainCmd.Flags().StringVar(&explainAttempt, "attempt", "", "legacy alias for --execution-scope")
	explainCmd.Flags().StringVar(&explainToolCall, "tool-call", "", "tool call id")
	explainCmd.Flags().StringVar(&explainProcess, "process", "", "process id")
	explainCmd.Flags().StringVar(&explainEvent, "event", "", "runtime event id")
	explainCmd.Flags().StringVar(&explainRisk, "risk", "", "policy decision id")
	explainCmd.Flags().StringVar(&explainFile, "file", "", "workspace-relative file path")
	_ = explainCmd.Flags().MarkHidden("attempt")
	explainCmd.Flags().IntVar(&explainDepth, "depth", 2, "maximum graph traversal depth for causality_path")
	explainCmd.Flags().IntVar(&explainLimit, "limit", 100, "maximum graph edges returned in causality_path")
	explainCmd.Flags().StringVar(&explainCursor, "cursor", "", "pagination cursor from previous graph explain output")
	explainCmd.Flags().BoolVar(&explainJSON, "json", false, "emit structured explain JSON")

	cmd := &cobra.Command{Use: "graph", Short: "provenance graph commands"}
	cmd.AddCommand(trace)
	cmd.AddCommand(refs)
	cmd.AddCommand(logCmd)
	cmd.AddCommand(materialize)
	cmd.AddCommand(materializeLLM)
	cmd.AddCommand(objectsCmd)
	cmd.AddCommand(diffCmd)
	cmd.AddCommand(blameCmd)
	cmd.AddCommand(verifyCmd)
	cmd.AddCommand(replayCmd)
	cmd.AddCommand(trajectoriesCmd)
	cmd.AddCommand(lensCmd)
	cmd.AddCommand(explainCmd)
	return cmd
}
