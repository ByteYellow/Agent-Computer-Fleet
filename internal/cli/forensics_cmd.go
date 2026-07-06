package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCmd(dataDir, daemonURL *string) *cobra.Command {
	var jsonOut bool
	var batchID string
	var runID string
	var jobID string
	var shardID string
	var latest bool
	var limit int
	var includeRunBundles bool
	var includeEvalContexts bool
	var signKey string
	export := &cobra.Command{
		Use:   "export <run_id>",
		Short: "export a forensics bundle for a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, err := exportForensics(*dataDir, *daemonURL, args[0], signKey)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s path=%s sha256=%s size_bytes=%d signed=%t attestation=%s\n",
				bundle.ID, bundle.Path, bundle.SHA256, bundle.SizeBytes, bundle.Signed, bundle.AttestationPath)
			return nil
		},
	}
	export.Flags().BoolVar(&jsonOut, "json", false, "emit structured forensics export JSON")
	export.Flags().StringVar(&signKey, "sign-key", "", "hex ed25519 private key file; when set, writes a .dsse.json attestation over the bundle")
	exportBatch := &cobra.Command{
		Use:   "export-batch",
		Short: "export a batch-level forensics audit bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := forensics.BatchExportOptions{
				BatchID:             batchID,
				RunID:               runID,
				JobID:               jobID,
				ShardID:             shardID,
				Latest:              latest,
				Limit:               limit,
				IncludeRunBundles:   includeRunBundles,
				IncludeEvalContexts: includeEvalContexts,
			}
			bundle, err := exportBatchForensics(*dataDir, *daemonURL, opts)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s batch=%s runs=%d items=%d path=%s sha256=%s size_bytes=%d\n",
				bundle.ID, bundle.BatchID, bundle.RunCount, bundle.ItemCount, bundle.Path, bundle.SHA256, bundle.SizeBytes)
			if len(bundle.RunBundles) > 0 {
				refs := make([]string, 0, len(bundle.RunBundles))
				for _, runBundle := range bundle.RunBundles {
					refs = append(refs, runBundle.RunID+"="+runBundle.SHA256)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "run_bundles=%s\n", strings.Join(refs, ","))
			}
			return nil
		},
	}
	exportBatch.Flags().StringVar(&batchID, "batch", "", "record batch id")
	exportBatch.Flags().StringVar(&runID, "run", "", "run id")
	exportBatch.Flags().StringVar(&jobID, "job", "", "job id")
	exportBatch.Flags().StringVar(&shardID, "shard", "", "shard id")
	exportBatch.Flags().BoolVar(&latest, "latest", false, "export only the latest batch matching filters")
	exportBatch.Flags().IntVar(&limit, "limit", 100, "maximum batch items to include")
	exportBatch.Flags().BoolVar(&includeRunBundles, "include-run-bundles", true, "export and reference per-run forensics bundles")
	exportBatch.Flags().BoolVar(&includeEvalContexts, "include-eval-contexts", false, "embed EvalContext records in the batch bundle")
	exportBatch.Flags().BoolVar(&jsonOut, "json", false, "emit structured batch forensics export JSON")
	var importPubKey string
	importCmd := &cobra.Command{
		Use:   "import <bundle.json|bundle.json.gz>",
		Short: "import a forensics bundle into the local store (replay a captured run)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := importForensics(*dataDir, args[0], importPubKey)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "imported run=%s rows=%d objects=%d snapshot_files=%d omitted=%d bundle_schema=%s\n",
				info.RunID, info.TotalRows, info.ObjectBlobs, info.SnapshotFiles, info.Omitted, info.BundleSchema)
			tables := make([]string, 0, len(info.Tables))
			for t := range info.Tables {
				tables = append(tables, t)
			}
			sort.Strings(tables)
			for _, t := range tables {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s=%d\n", t, info.Tables[t])
			}
			return nil
		},
	}
	importCmd.Flags().BoolVar(&jsonOut, "json", false, "emit structured forensics import JSON")
	importCmd.Flags().StringVar(&importPubKey, "pub-key", "", "hex ed25519 public key file; when set, verify the bundle's .dsse.json attestation before importing")
	cmd := &cobra.Command{Use: "forensics", Short: "forensics bundle commands"}
	cmd.AddCommand(export)
	cmd.AddCommand(exportBatch)
	cmd.AddCommand(importCmd)
	cmd.AddCommand(forensicsVerifyAttestationCmd())
	cmd.AddCommand(forensicsKeygenCmd())
	return cmd
}

func importForensics(dataDir, bundlePath, pubKeyPath string) (forensics.ImportInfo, error) {
	// Verify-before-import: if a public key is supplied, the bundle's DSSE
	// attestation must verify against the on-disk bytes (catches a tampered or
	// substituted bundle before any of it touches the store).
	if pubKeyPath != "" {
		pub, err := attest.LoadPublicKeyHex(pubKeyPath)
		if err != nil {
			return forensics.ImportInfo{}, err
		}
		attPath := forensicsAttestationPath(bundlePath)
		if err := forensics.VerifyBundleAttestation(bundlePath, attPath, pub); err != nil {
			return forensics.ImportInfo{}, fmt.Errorf("attestation verify failed: %w", err)
		}
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return forensics.ImportInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return forensics.ImportInfo{}, err
	}
	defer db.Close()
	svc := forensics.Service{DB: db, Paths: paths}
	return svc.ImportBundle(bundlePath)
}

func forensicsAttestationPath(bundlePath string) string {
	path := strings.TrimSuffix(bundlePath, ".gz")
	path = strings.TrimSuffix(path, ".json")
	return path + ".dsse.json"
}

func exportForensics(dataDir, daemonURL, runID, signKeyPath string) (forensics.BundleInfo, error) {
	// Signing uses a local key, so a --sign-key export always runs against the
	// local store rather than the daemon.
	if signKeyPath == "" {
		if client, ok := daemonClient(daemonURL); ok {
			return client.ExportForensics(runID)
		}
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return forensics.BundleInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return forensics.BundleInfo{}, err
	}
	defer db.Close()
	svc := forensics.Service{DB: db, Paths: paths}
	if signKeyPath != "" {
		key, err := attest.LoadPrivateKeyHex(signKeyPath)
		if err != nil {
			return forensics.BundleInfo{}, err
		}
		svc.SignKey = key
		svc.SignKeyID = attest.KeyID(key.Public().(ed25519.PublicKey))
	}
	return svc.ExportBundle(runID)
}

func forensicsVerifyAttestationCmd() *cobra.Command {
	var pubKey string
	cmd := &cobra.Command{
		Use:   "verify-attestation <bundle> <attestation>",
		Short: "verify a DSSE attestation against a forensics bundle and public key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if pubKey == "" {
				return fmt.Errorf("--pub-key is required")
			}
			pub, err := attest.LoadPublicKeyHex(pubKey)
			if err != nil {
				return err
			}
			if err := forensics.VerifyBundleAttestation(args[0], args[1], pub); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok attestation verifies bundle=%s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&pubKey, "pub-key", "", "hex ed25519 public key file")
	return cmd
}

func forensicsKeygenCmd() *cobra.Command {
	var privPath, pubPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "generate an ed25519 keypair (hex) for forensics attestation signing",
		RunE: func(cmd *cobra.Command, args []string) error {
			if privPath == "" || pubPath == "" {
				return fmt.Errorf("--priv and --pub are required")
			}
			pub, priv, keyID, err := attest.GenerateKey()
			if err != nil {
				return err
			}
			if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key_id=%s priv=%s pub=%s\n", keyID, privPath, pubPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&privPath, "priv", "", "output path for the hex private key (seed)")
	cmd.Flags().StringVar(&pubPath, "pub", "", "output path for the hex public key")
	return cmd
}

func exportBatchForensics(dataDir, daemonURL string, opts forensics.BatchExportOptions) (forensics.BatchBundleInfo, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.ExportBatchForensics(opts)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return forensics.BatchBundleInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return forensics.BatchBundleInfo{}, err
	}
	defer db.Close()
	return (forensics.Service{DB: db, Paths: paths}).ExportBatch(opts)
}
