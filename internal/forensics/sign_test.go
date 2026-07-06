package forensics

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// TestSignedBundleVerifiesAndDetectsTamper is the B1 end-to-end guarantee: a
// signed forensics bundle verifies against the signing key, and a post-signing
// rewrite of the bundle on disk fails verification (tamper-evidence the plain
// sha256 recompute cannot provide).
func TestSignedBundleVerifiesAndDetectsTamper(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Minimal run so the bundle has a row to anchor (a lease is enough).
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('l1','run-sign','t.yaml','{}','allocated',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}

	pub, priv, keyID, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, Paths: paths, SignKey: priv, SignKeyID: keyID}
	info, err := svc.ExportBundle("run-sign")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Signed || info.AttestationPath == "" {
		t.Fatalf("bundle not signed: %+v", info)
	}

	// Untampered bundle verifies.
	if err := VerifyBundleAttestation(info.Path, info.AttestationPath, pub); err != nil {
		t.Fatalf("verify signed bundle: %v", err)
	}
	gzPath := info.Path + ".gz"
	writeGzipFile(t, gzPath, mustReadFile(t, info.Path))
	if err := VerifyBundleAttestation(gzPath, info.AttestationPath, pub); err != nil {
		t.Fatalf("verify gzipped signed bundle: %v", err)
	}

	// Tamper the bundle on disk, then verification must fail.
	if err := os.WriteFile(info.Path, []byte(`{"tampered":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleAttestation(info.Path, info.AttestationPath, pub); err == nil {
		t.Fatal("verification accepted a tampered bundle - B1 tamper-evidence broken")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeGzipFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(raw); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedBundleHasNoAttestation(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('l1','run-unsigned','t.yaml','{}','allocated',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	info, err := (Service{DB: db, Paths: paths}).ExportBundle("run-unsigned")
	if err != nil {
		t.Fatal(err)
	}
	if info.Signed || info.AttestationPath != "" {
		t.Fatalf("unsigned export should have no attestation: %+v", info)
	}
	if _, err := os.Stat(filepath.Join(paths.Artifacts, info.ID+".dsse.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected attestation file for unsigned bundle")
	}
}
