package producer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectTLSTargetNonELFIsZero(t *testing.T) {
	// A missing file and a non-ELF file must both yield a zero target (the caller
	// then falls through to whatever was explicitly configured), not a panic.
	if got := DetectTLSTarget(filepath.Join(t.TempDir(), "does-not-exist")); got != (TLSTarget{}) {
		t.Errorf("missing file: got %+v, want zero", got)
	}
	txt := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(txt, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectTLSTarget(txt); got != (TLSTarget{}) {
		t.Errorf("non-ELF file: got %+v, want zero", got)
	}
}

func TestResolveSharedLibMissingIsEmpty(t *testing.T) {
	if p := resolveSharedLib("libssl.so.this-does-not-exist"); p != "" {
		t.Errorf("resolveSharedLib on a missing soname returned %q, want empty", p)
	}
}
