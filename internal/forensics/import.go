package forensics

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// ImportInfo summarizes a bundle import: which run was loaded and how many rows
// landed in each table.
type ImportInfo struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	BundlePath    string         `json:"bundle_path"`
	BundleSchema  string         `json:"bundle_schema"`
	Tables        map[string]int `json:"tables"`
	TotalRows     int            `json:"total_rows"`
	ObjectBlobs   int            `json:"object_blobs"`
	SnapshotFiles int            `json:"snapshot_files"`
	Omitted       int            `json:"omitted_content"`
}

// importTableOrder lists the bundle table keys to load, parents before children,
// so the import works even if foreign keys are enforced. A bundle that omits a
// key (older export, or a run with no orchestration) simply skips it — import is
// tolerant of absent keys and unknown bundle versions by design.
var importTableOrder = []string{
	"leases",
	"sessions",
	"execution_context_bindings",
	"rollouts",
	"snapshots",
	"tool_calls",
	"agents",
	"fork_attempts",
	"processes",
	"events",
	"policy_decisions",
	"risk_signals",
	"signals",
	"response_actions",
	"external_effects",
	"evidence_events",
	"graph_edges",
	"cost_samples",
	"provenance_objects",
}

// ImportBundle re-hydrates a forensics bundle into the local store so the run can
// be browsed and replayed exactly as captured. It is the playback half of
// "capture once, replay anywhere": export (optionally signed) on the sandbox/VM,
// import into a fresh `init`'d store on any machine. Rows are inserted verbatim
// with INSERT OR REPLACE inside a single transaction.
func (s Service) ImportBundle(path string) (ImportInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ImportInfo{}, fmt.Errorf("read bundle: %w", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return ImportInfo{}, fmt.Errorf("decode bundle: %w", err)
	}
	runID, _ := bundle["run_id"].(string)
	if runID == "" {
		return ImportInfo{}, fmt.Errorf("bundle has no run_id")
	}
	bundleSchema, _ := bundle["schema_version"].(string)

	// Verify embedded object content up front: blobs are content-addressed, so
	// re-hash each and hard-fail on any mismatch BEFORE the row tx commits, so a
	// tampered artifact can never enter the store. The actual write + path rewrite
	// happens in restoreEmbeddedContent once the rows are committed.
	for _, b := range tableRows(bundle, "object_blobs") {
		hash, _ := b["hash"].(string)
		enc, _ := b["content_b64"].(string)
		content, decErr := base64.StdEncoding.DecodeString(enc)
		if decErr != nil {
			return ImportInfo{}, fmt.Errorf("decode object %s: %w", hash, decErr)
		}
		if err := verifyBundleContentHash(hash, content); err != nil {
			return ImportInfo{}, err
		}
	}

	// Replay imports a consistent snapshot whose integrity was already enforced at
	// capture time. Re-checking foreign keys here would force exporting every
	// ancestor table even ones the graph never renders (and chasing each table's
	// scoping filter), so we disable FK enforcement on a dedicated connection and
	// rely on the lens round-trip diff as the real fidelity check. A dedicated
	// conn keeps the pragma from leaking to other pooled connections.
	ctx := context.Background()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return ImportInfo{}, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return ImportInfo{}, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ImportInfo{}, err
	}
	defer func() { _ = tx.Rollback() }()

	info := ImportInfo{
		SchemaVersion: "agentprovenance.forensics_import/v1",
		RunID:         runID,
		BundlePath:    path,
		BundleSchema:  bundleSchema,
		Tables:        map[string]int{},
	}
	for _, table := range importTableOrder {
		rows := tableRows(bundle, table)
		if len(rows) == 0 {
			continue
		}
		n, err := insertRows(tx, table, rows)
		if err != nil {
			return ImportInfo{}, err
		}
		info.Tables[table] = n
		info.TotalRows += n
	}

	if err := tx.Commit(); err != nil {
		return ImportInfo{}, err
	}
	// Write verified blobs + snapshot files to this store and rewrite their (now
	// machine-local) paths in the committed rows.
	objectBlobs, snapshotFiles, omitted, err := s.restoreEmbeddedContent(bundle, runID)
	if err != nil {
		return ImportInfo{}, err
	}
	info.ObjectBlobs = objectBlobs
	info.SnapshotFiles = snapshotFiles
	info.Omitted = omitted
	return info, nil
}

func (s Service) restoreEmbeddedContent(bundle map[string]any, runID string) (int, int, int, error) {
	objectCount, err := s.restoreObjectBlobs(tableRows(bundle, "object_blobs"))
	if err != nil {
		return 0, 0, 0, err
	}
	snapshotCount, err := s.restoreSnapshotFiles(runID, tableRows(bundle, "snapshot_files"))
	if err != nil {
		return 0, 0, 0, err
	}
	return objectCount, snapshotCount, len(tableRows(bundle, "omitted_content")), nil
}

func (s Service) restoreObjectBlobs(rows []map[string]any) (int, error) {
	count := 0
	for _, row := range rows {
		hash, _ := row["hash"].(string)
		contentB64, _ := row["content_b64"].(string)
		if hash == "" || contentB64 == "" {
			continue
		}
		content, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			return count, fmt.Errorf("decode object %s: %w", hash, err)
		}
		if err := verifyBundleContentHash(hash, content); err != nil {
			return count, err
		}
		path := importedObjectPath(s.Paths, hash)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return count, err
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return count, err
		}
		if _, err := s.DB.Exec(`UPDATE provenance_objects SET path = ?, size_bytes = ? WHERE hash = ?`, path, len(content), hash); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s Service) restoreSnapshotFiles(runID string, rows []map[string]any) (int, error) {
	count := 0
	roots := map[string]string{}
	for _, row := range rows {
		snapshotID, _ := row["snapshot_id"].(string)
		name, _ := row["name"].(string)
		contentB64, _ := row["content_b64"].(string)
		if snapshotID == "" || name == "" || contentB64 == "" {
			continue
		}
		rel, err := cleanBundleRelPath(name)
		if err != nil {
			return count, fmt.Errorf("snapshot %s: %w", snapshotID, err)
		}
		content, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			return count, fmt.Errorf("decode snapshot %s/%s: %w", snapshotID, rel, err)
		}
		root := roots[snapshotID]
		if root == "" {
			root = filepath.Join(s.Paths.Snapshots, "imported", runID, snapshotID)
			roots[snapshotID] = root
		}
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return count, err
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return count, err
		}
		count++
	}
	for snapshotID, root := range roots {
		if _, err := s.DB.Exec(`UPDATE snapshots SET path = ? WHERE id = ?`, root, snapshotID); err != nil {
			return count, err
		}
	}
	return count, nil
}

// tableRows pulls a bundle table key into a slice of column->value maps, tolerating
// an absent or wrongly-typed key (returns nil so the table is skipped).
func tableRows(bundle map[string]any, key string) []map[string]any {
	raw, ok := bundle[key].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// insertRows writes each row into the table by its own column names, so it stays
// correct regardless of schema column order or which columns the export carried.
// SQLite's type affinity coerces JSON float64s back into INTEGER/REAL columns, so
// numeric ids and pids round-trip without explicit conversion.
func insertRows(tx *sql.Tx, table string, rows []map[string]any) (int, error) {
	allowed, err := tableColumns(tx, table)
	if err != nil {
		return 0, err
	}
	tableIdent, err := quoteIdent(table)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, row := range rows {
		cols := make([]string, 0, len(row))
		for k := range row {
			if _, ok := allowed[k]; !ok {
				return count, fmt.Errorf("bundle row for %s contains unknown column %q", table, k)
			}
			cols = append(cols, k)
		}
		sort.Strings(cols)
		if len(cols) == 0 {
			continue
		}
		quoted := make([]string, len(cols))
		vals := make([]any, len(cols))
		for i, c := range cols {
			ident, err := quoteIdent(c)
			if err != nil {
				return count, err
			}
			quoted[i] = ident
			vals[i] = row[c]
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
		q := fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)", tableIdent, strings.Join(quoted, ","), placeholders)
		if _, err := tx.Exec(q, vals...); err != nil {
			return count, fmt.Errorf("insert into %s: %w", table, err)
		}
		count++
	}
	return count, nil
}

func tableColumns(tx *sql.Tx, table string) (map[string]struct{}, error) {
	tableIdent, err := quoteIdent(table)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query("PRAGMA table_info(" + tableIdent + ")")
	if err != nil {
		return nil, fmt.Errorf("read columns for %s: %w", table, err)
	}
	defer rows.Close()
	cols := map[string]struct{}{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("unknown import table %q", table)
	}
	return cols, nil
}

func quoteIdent(ident string) (string, error) {
	if ident == "" {
		return "", fmt.Errorf("empty SQL identifier")
	}
	for i, r := range ident {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return "", fmt.Errorf("invalid SQL identifier %q", ident)
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return "", fmt.Errorf("invalid SQL identifier %q", ident)
		}
	}
	return `"` + ident + `"`, nil
}

func importedObjectPath(paths store.Paths, hash string) string {
	clean := strings.TrimPrefix(hash, "sha256:")
	prefix := clean
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(paths.Provenance, "objects", "sha256", prefix, clean+".json")
}

func verifyBundleContentHash(hash string, content []byte) error {
	want := strings.TrimPrefix(hash, "sha256:")
	if want == "" {
		return fmt.Errorf("object hash is empty")
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid object hash %q: %w", hash, err)
	}
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("object blob hash mismatch: expected=%s actual=%s", hash, "sha256:"+got)
	}
	return nil
}

func cleanBundleRelPath(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("snapshot file path must be relative: %q", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("snapshot file path escapes snapshot root: %q", name)
	}
	return clean, nil
}
