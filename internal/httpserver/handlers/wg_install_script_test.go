package handlers

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// Installer must stay valid bash in every transport mode.
func TestRenderInstallScriptBashSyntax(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	modes := []installTransport{
		{Mode: "udp"},
		{Mode: "auto", WssURL: "wss://node.example.com:443", ListenPort: 51820},
		{Mode: "wss", WssURL: "wss://node.example.com:443", ListenPort: 51820},
	}
	for _, tr := range modes {
		s := renderInstallScript("https://panel.example.com", strings.Repeat("a", 64), tr)
		f, err := os.CreateTemp(t.TempDir(), "install*.sh")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		f.Close()
		out, err := exec.Command("bash", "-n", f.Name()).CombinedOutput()
		if err != nil {
			t.Fatalf("mode %s: bash -n failed: %v\n%s", tr.Mode, err, out)
		}
		if !strings.Contains(s, "docker_dns_install") {
			t.Fatalf("mode %s: docker DNS helper missing", tr.Mode)
		}
		if strings.Contains(s, "token=") {
			t.Fatalf("mode %s: token in a URL", tr.Mode)
		}
	}
	stub := renderInstallStub("https://panel.example.com")
	f, err := os.CreateTemp(t.TempDir(), "stub*.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(stub)
	f.Close()
	if out, err := exec.Command("bash", "-n", f.Name()).CombinedOutput(); err != nil {
		t.Fatalf("stub: bash -n failed: %v\n%s", err, out)
	}
	// No terminal and no --token-file: must refuse instead of fetching anything.
	cmd := exec.Command("bash", f.Name())
	cmd.Stdin = strings.NewReader("")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // no controlling terminal
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "missing or malformed") {
		t.Fatalf("stub without token: err=%v out=%s", err, out)
	}
}
