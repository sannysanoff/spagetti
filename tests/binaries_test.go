package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// proc is a child process whose output can be polled.
type proc struct {
	t      *testing.T
	name   string
	cmd    *exec.Cmd
	mu     sync.Mutex
	out    bytes.Buffer
	done   chan error
	env    []string
	failed bool
}

func startProc(t *testing.T, root string, name string, bin string, env []string, args ...string) *proc {
	t.Helper()
	p := &proc{t: t, name: name, done: make(chan error, 1), env: env}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Dir = root
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout = p
	p.cmd.Stderr = p
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("%s: start: %v", name, err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
		}
		if p.failed {
			t.Logf("--- %s output ---\n%s", name, p.snapshot())
		}
	})
	return p
}

func (p *proc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Write(b)
}

func (p *proc) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

func (p *proc) waitFor(t *testing.T, re *regexp.Regexp, d time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(p.snapshot()); m != nil {
			return m
		}
		select {
		case <-p.done:
			t.Fatalf("%s exited before matching %v:\n%s", p.name, re, p.snapshot())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never matched %v:\n%s", p.name, re, p.snapshot())
	return nil
}

// TestBinariesEndToEnd builds and runs the three shipped commands and drives them
// the way an operator would: gateway, wrapped server, then the call client.
func TestBinariesEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs three binaries")
	}
	root := moduleRoot(t)
	binDir := t.TempDir()
	build := func(pkg string) string {
		t.Helper()
		out := filepath.Join(binDir, filepath.Base(pkg))
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, b)
		}
		return out
	}
	gatewayBin := build("./cmd/spagetti-gateway")
	echoBin := build("./examples/echo-server")
	callBin := build("./cmd/spagetti-call")

	work := t.TempDir()
	confDir := filepath.Join(work, "conf")
	cfgPath := filepath.Join(work, "gateway.json")
	initCmd := exec.Command(gatewayBin, "-init", cfgPath)
	if b, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("gateway -init: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Tokens []struct {
			Name  string   `json:"name"`
			Kind  string   `json:"kind"`
			Token string   `json:"token"`
			Allow []string `json:"allow"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var serverToken, clientToken string
	for _, tok := range cfg.Tokens {
		switch tok.Kind {
		case "server":
			serverToken = tok.Token
		case "client":
			clientToken = tok.Token
		}
	}
	if serverToken == "" || clientToken == "" {
		t.Fatalf("starter config is missing tokens: %s", raw)
	}

	gw := startProc(t, root, "gateway", gatewayBin, nil, "-config", cfgPath, "-addr", "127.0.0.1:0")
	addr := gw.waitFor(t, regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`), 15*time.Second)[1]
	wsURL := "ws://" + addr + "/ws"
	t.Logf("gateway at %s", wsURL)

	env := []string{"SPAGETTI_CONF_DIR=" + confDir}
	echo := startProc(t, root, "echo-server", echoBin, env,
		"-gateway", wsURL, "-token", serverToken, "-id", "example", "-name", "Example")
	_ = echo

	call := func(timeout time.Duration, args ...string) (string, string, error) {
		t.Helper()
		full := append([]string{"-gateway", wsURL, "-token", clientToken, "-conf", confDir, "-client-id", "caller"}, args...)
		cmd := exec.Command(callBin, full...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), env...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return out.String(), errb.String(), err
		case <-time.After(timeout):
			cmd.Process.Kill()
			<-done
			t.Fatalf("spagetti-call %v timed out", args)
			return "", "", nil
		}
	}

	// The server must come online before the client can reach it.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if out, _, err := call(10*time.Second, "list"); err == nil && strings.Contains(out, "example") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never appeared in the directory:\n%s", echo.snapshot())
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Pin the server exactly as an operator would: copy the two generated files.
	pub := filepath.Join(confDir, "servers", "example", "identity.pub")
	pw := filepath.Join(confDir, "servers", "example", "access.password")
	if out, errOut, err := call(15*time.Second, "pin", "-server", "example", "-pub", pub, "-password", pw); err != nil {
		t.Fatalf("pin: %v\n%s%s", err, out, errOut)
	} else if !strings.Contains(out, "pinned example") {
		t.Fatalf("pin output: %q", out)
	}

	out, errOut, err := call(15*time.Second, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s%s", err, out, errOut)
	}
	if !strings.Contains(out, "example") || !strings.Contains(out, "online=true") {
		t.Fatalf("directory listing: %q", out)
	}

	out, errOut, err = call(15*time.Second, "get", "example", "/whoami")
	if err != nil {
		t.Fatalf("whoami: %v\n%s%s", err, out, errOut)
	}
	if !strings.Contains(out, "HTTP 200") || !strings.Contains(out, `"id":"caller"`) {
		t.Fatalf("the server did not see the authenticated caller: %q", out)
	}

	out, errOut, err = call(15*time.Second, "post", "example", "/echo/body", "hello")
	if err != nil {
		t.Fatalf("post: %v\n%s%s", err, out, errOut)
	}
	if !strings.Contains(out, `"bytes":5`) {
		t.Fatalf("body echo: %q", out)
	}

	out, errOut, err = call(30*time.Second, "sse", "example", "/events")
	if err != nil {
		t.Fatalf("sse: %v\n%s%s", err, out, errOut)
	}
	if got := strings.Count(out, "data: event"); got != 5 {
		t.Fatalf("sse delivered %d events: %q", got, out)
	}
	if !strings.Contains(out, "[DONE]") {
		t.Fatalf("sse did not complete: %q", out)
	}
	if !regexp.MustCompile(`first chunk after \d+`).MatchString(errOut) {
		t.Fatalf("sse did not report incremental arrival: %q", errOut)
	}

	out, errOut, err = call(15*time.Second, "ws", "example", "/ws", "hello")
	if err != nil {
		t.Fatalf("ws: %v\n%s%s\necho log:\n%s\ngateway log:\n%s", err, out, errOut, echo.snapshot(), gw.snapshot())
	}
	if !strings.Contains(out, "websocket echo: echo: hello") {
		t.Fatalf("websocket echo: %q\necho log:\n%s", out, echo.snapshot())
	}

	// And a wrong bearer token must be refused by the gateway.
	cmd := exec.Command(callBin, "-gateway", wsURL, "-token", "wrong-token-aaaaaaaaaaaaaaaaaaaaaaaa", "-conf", confDir, "list")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("a wrong bearer token was accepted: %s", b)
	}
	t.Logf("gateway log:\n%s", gw.snapshot())
	fmt.Println()
}
