package launch

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestPreflightRecognizesClaudeHooks(t *testing.T) {
	r := Preflight(Options{
		Command:       []string{"claude", "--print", "hi"},
		Dashboard:     true,
		DashboardAddr: "127.0.0.1:0",
		Sensor:        "off",
		SelfExe:       os.Args[0],
	})
	got := findCheck(t, r, "Claude hooks")
	if got.Status != CheckPass {
		t.Fatalf("Claude hooks status=%s detail=%q", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "per-run") {
		t.Fatalf("unexpected hook detail: %q", got.Detail)
	}
}

func TestPreflightWarnsWhenClaudeSettingsAlreadyPresent(t *testing.T) {
	r := Preflight(Options{
		Command:       []string{"claude", "--settings", "mine.json"},
		Dashboard:     true,
		DashboardAddr: "127.0.0.1:0",
		Sensor:        "off",
		SelfExe:       os.Args[0],
	})
	got := findCheck(t, r, "Claude hooks")
	if got.Status != CheckWarn {
		t.Fatalf("Claude hooks status=%s, want warn", got.Status)
	}
}

func TestPreflightWarnsWhenDashboardPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := Preflight(Options{
		Command:       []string{"sh", "-c", "true"},
		Dashboard:     true,
		DashboardAddr: ln.Addr().String(),
		Sensor:        "off",
		SelfExe:       os.Args[0],
	})
	got := findCheck(t, r, "dashboard port")
	if got.Status != CheckWarn {
		t.Fatalf("dashboard status=%s detail=%q", got.Status, got.Detail)
	}
}

func TestPreflightSensorOffSkips(t *testing.T) {
	r := Preflight(Options{
		Command:       []string{"sh", "-c", "true"},
		Dashboard:     true,
		DashboardAddr: "127.0.0.1:0",
		Sensor:        "off",
		SelfExe:       os.Args[0],
	})
	got := findCheck(t, r, "kernel sensor")
	if got.Status != CheckSkip {
		t.Fatalf("sensor status=%s, want skip", got.Status)
	}
}

func TestPrintPreflight(t *testing.T) {
	var buf bytes.Buffer
	PrintPreflight(&buf, PreflightReport{Checks: []Check{
		{Name: "dashboard port", Status: CheckPass, Detail: "ok"},
		{Name: "kernel sensor", Status: CheckWarn, Detail: "no caps", Fix: "setcap"},
	}})
	out := buf.String()
	for _, want := range []string{"agentprov preflight", "dashboard port", "kernel sensor", "fix: setcap"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPreflightJSONShape(t *testing.T) {
	r := Preflight(Options{
		Command:       []string{"sh", "-c", "true"},
		Dashboard:     true,
		DashboardAddr: "127.0.0.1:0",
		Sensor:        "off",
		SelfExe:       os.Args[0],
	})
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"checks"`)) {
		t.Fatalf("json missing checks: %s", raw)
	}
	// Keep the platform-dependent cgroup check honest but non-brittle.
	cg := findCheck(t, r, "cgroup v2")
	if runtime.GOOS == "linux" && cg.Status == CheckSkip {
		t.Fatalf("linux cgroup check should not be skipped: %+v", cg)
	}
}

func findCheck(t *testing.T, r PreflightReport, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %+v", name, r.Checks)
	return Check{}
}
