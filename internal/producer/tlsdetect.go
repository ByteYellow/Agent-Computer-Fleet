package producer

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
)

// TLSTarget says where to point the sensor's TLS uprobes for a specific
// executable, so an agent's model-intent is captured without the operator hand-
// picking a libssl path per runtime.
type TLSTarget struct {
	// SSLLib is the path to attach the SSL_write/read (+ _ex) uprobes to: a
	// dynamic libssl file, or the binary itself for a statically-linked OpenSSL
	// (e.g. node). Feeds sensor Options.SSLLib / AGENTPROV_SSL_LIB.
	SSLLib string
	// GoTLSBin is the binary to attach the crypto/tls.(*Conn).Write uprobe to.
	// Feeds sensor Options.GoTLSBin / AGENTPROV_GO_TLS_BIN.
	GoTLSBin string
	// Stack is the identified TLS stack, for the capability report / logging.
	Stack string // "go" | "openssl-static" | "openssl-dynamic" | "" (unknown)
}

// DetectTLSTarget inspects an executable's ELF and decides where TLS plaintext
// can be captured:
//   - Go (crypto/tls.(*Conn).Write symbol present)  -> GoTLSBin = exe
//   - statically-linked OpenSSL (SSL_write in ELF)   -> SSLLib   = exe (e.g. node)
//   - dynamically-linked OpenSSL (imports libssl.so) -> SSLLib   = resolved libssl path
//
// Best-effort: a zero TLSTarget means the stack could not be identified (a
// stripped Go binary, static non-OpenSSL TLS like BoringSSL/rustls, or an
// unreadable/non-ELF file), and the caller should fall through to whatever was
// explicitly configured.
func DetectTLSTarget(exePath string) TLSTarget {
	f, err := elf.Open(exePath)
	if err != nil {
		return TLSTarget{}
	}
	defer f.Close()

	hasSym := func(name string) bool {
		for _, list := range [][]elf.Symbol{symsOf(f.Symbols), symsOf(f.DynamicSymbols)} {
			for _, s := range list {
				if s.Name == name {
					return true
				}
			}
		}
		return false
	}

	if hasSym("crypto/tls.(*Conn).Write") {
		return TLSTarget{GoTLSBin: exePath, Stack: "go"}
	}
	if hasSym("SSL_write") { // static OpenSSL baked into the binary (e.g. node)
		return TLSTarget{SSLLib: exePath, Stack: "openssl-static"}
	}
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		if strings.HasPrefix(lib, "libssl.so") {
			t := TLSTarget{Stack: "openssl-dynamic"}
			if p := resolveSharedLib(lib); p != "" {
				t.SSLLib = p
			}
			return t
		}
	}
	return TLSTarget{}
}

func symsOf(fn func() ([]elf.Symbol, error)) []elf.Symbol {
	s, _ := fn()
	return s
}

// resolveSharedLib finds a shared library file by soname in the common multiarch
// and default library directories (best-effort; the dynamic linker's full search
// is not replicated). Empty when not found.
func resolveSharedLib(soname string) string {
	dirs := []string{
		"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
		"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"/lib64", "/usr/lib64", "/lib", "/usr/lib",
	}
	for _, d := range dirs {
		p := filepath.Join(d, soname)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
