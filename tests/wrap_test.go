package tests

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/gateway"
)

// buildCmd builds one command from the module root into dir.
func buildCmd(t *testing.T, root, dir, pkg string) string {
	t.Helper()
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

// cleanEnv is os.Environ without any SPAGETTY_ variable, so a test never inherits
// wrapper settings from the shell that runs it.
func cleanEnv(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SPAGETTY_") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

// secretFile writes an env file the way an operator would keep it.
func secretFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWrap starts the wrapper and waits for it to either refuse (an error and an
// immediate exit) or settle into retrying (a timeout and a kill). Settings that
// are accepted leave a process that keeps trying to reach its gateway, which is
// how the "did the configuration pass?" cases are told apart from refusals.
func runWrap(t *testing.T, bin, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(cleanEnv(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wrapper: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(1500 * time.Millisecond):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), nil
	}
}

func stopProc(p *proc) {
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
	}
}

// TestWrapPublishesATargetWebserver drives cmd/spagetti-wrap the way an operator
// does: a target webserver that knows nothing about spagetti, an env file, and a
// client that pins what the wrapper wrote and calls through the tunnel.
func TestWrapPublishesATargetWebserver(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs binaries")
	}
	root := moduleRoot(t)
	binDir := t.TempDir()
	wrapBin := buildCmd(t, root, binDir, "./cmd/spagetti-wrap")
	callBin := buildCmd(t, root, binDir, "./cmd/spagetti-call")

	// The target: an ordinary webserver. It reports the verb, the path and the
	// caller the wrapper told it about.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "target %s %s peer=%s\n", r.Method, r.URL.Path, r.Header.Get("X-Spagetti-Peer"))
	}))
	defer target.Close()

	serverTok, clientTok, password := randToken(t), randToken(t), randToken(t)
	gw, err := gateway.New(gateway.Config{
		Tokens: []gateway.Token{
			{Name: "srv", Kind: "server", Token: serverTok, Allow: []string{"wrapped"}},
			{Name: "cli", Kind: "client", Token: clientTok, Allow: []string{"*"}},
		},
		Logf: func(format string, args ...any) { t.Logf("gw: "+format, args...) },
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	work := t.TempDir()
	keys := filepath.Join(work, "keys")
	envPath := filepath.Join(work, "wrap.env")
	secretFile(t, envPath, strings.Join([]string{
		"# the webserver to publish, and the name clients will ask for",
		"SPAGETTY_TARGET=" + target.URL,
		"SPAGETTY_NAME=wrapped",
		"",
		"SPAGETTY_ENDPOINT=" + wsURL,
		"SPAGETTY_TOKEN=" + serverTok,
		// a quoted value with a trailing comment, as an operator would write it
		`SPAGETTY_PASSWORD="` + password + `"  # minted with openssl`,
		"SPAGETTY_KEYS=" + keys,
	}, "\n")+"\n")

	p := startProc(t, root, "wrap", wrapBin, nil, "-env", envPath)
	p.waitFor(t, regexp.MustCompile(`registered "wrapped" with the gateway`), 20*time.Second)
	startup := p.snapshot()
	if !strings.Contains(startup, "connecting to the gateway "+wsURL) {
		t.Errorf("the connection to the gateway was not logged:\n%s", startup)
	}
	if !strings.Contains(startup, "SPAGETTY_NAME: wrapped (") {
		t.Errorf("the resolved configuration was not logged with its origin:\n%s", startup)
	}
	if !strings.Contains(startup, "first run: minted the keypair into "+keys) {
		t.Errorf("the first run did not report minting the keypair:\n%s", startup)
	}
	if strings.Contains(startup, password) || strings.Contains(startup, serverTok) {
		t.Errorf("a secret was logged:\n%s", startup)
	}

	// The identity that is actually announced is the one the wrapper minted. The
	// library must not report a fingerprint from some other, unused keypair.
	pub, err := conf.LoadPub(keys + ".pub")
	if err != nil {
		t.Fatalf("reading the minted public key: %v", err)
	}
	wantFP := conf.Fingerprint(pub)
	if !strings.Contains(startup, "server \"wrapped\" fingerprint "+wantFP) {
		t.Errorf("the wrapper did not report the minted fingerprint %s:\n%s", wantFP, startup)
	}
	if !strings.Contains(startup, fmt.Sprintf("server %q ready (fingerprint %s,", "wrapped", wantFP)) {
		t.Errorf("the library reported a fingerprint other than the minted key %s:\n%s", wantFP, startup)
	}

	// the files a client pins exist with the documented modes
	if fi, err := os.Stat(keys); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("keys file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(keys + ".password"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("password file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(keys + ".pub"); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("public key file mode = %v (%v), want 0644", fi.Mode().Perm(), err)
	}

	clientConf := filepath.Join(work, "client")
	call := func(args ...string) (string, string, error) {
		full := append([]string{"-gateway", wsURL, "-token", clientTok, "-conf", clientConf, "-client-id", "caller"}, args...)
		cmd := exec.Command(callBin, full...)
		cmd.Dir = root
		cmd.Env = cleanEnv()
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		return out.String(), errb.String(), err
	}

	if _, stderr, err := call("pin", "-server", "wrapped", "-pub", keys+".pub", "-password", keys+".password"); err != nil {
		t.Fatalf("pin: %v\n%s", err, stderr)
	}
	list, stderr, err := call("list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, stderr)
	}
	if !strings.Contains(list, wantFP) {
		t.Errorf("the gateway does not list the minted fingerprint %s:\n%s", wantFP, list)
	}
	out, stderr, err := call("get", "wrapped", "/hello?tag=1")
	if err != nil {
		t.Fatalf("get through the tunnel: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "target GET /hello") {
		t.Fatalf("the target's answer did not come back: %q", out)
	}
	if !strings.Contains(out, "peer=spg1:") {
		t.Fatalf("the caller's fingerprint was not passed to the target: %q", out)
	}

	// one line per forwarded request: timestamp, verb, path
	reqLine := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6} GET /hello\?tag=1`)
	if !reqLine.MatchString(p.snapshot()) {
		t.Fatalf("no timestamped request line for the forwarded request:\n%s", p.snapshot())
	}

	// restarting reuses the cached keypair instead of minting a new identity
	fp := regexp.MustCompile(`server "wrapped" fingerprint (spg1:[0-9a-f]+)`).FindStringSubmatch(p.snapshot())
	if fp == nil {
		t.Fatalf("no fingerprint in the startup log:\n%s", p.snapshot())
	}
	stopProc(p)

	p2 := startProc(t, root, "wrap", wrapBin, nil, "-env", envPath)
	p2.waitFor(t, regexp.MustCompile(`server "wrapped" fingerprint spg1:`), 20*time.Second)
	if strings.Contains(p2.snapshot(), "first run: minted the keypair") {
		t.Errorf("the second run minted a new keypair instead of reusing %s:\n%s", keys, p2.snapshot())
	}
	fp2 := regexp.MustCompile(`server "wrapped" fingerprint (spg1:[0-9a-f]+)`).FindStringSubmatch(p2.snapshot())
	if fp2 == nil || fp2[1] != fp[1] {
		t.Errorf("fingerprint changed across restarts: %v -> %v", fp, fp2)
	}
}

// TestWrapRefusesMisconfiguration pins the refusals: a required key that no
// source supplies, an unreadable line, a password of the wrong length or scheme,
// and an env file that simply is not there.
func TestWrapRefusesMisconfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs binaries")
	}
	root := moduleRoot(t)
	wrapBin := buildCmd(t, root, t.TempDir(), "./cmd/spagetti-wrap")
	good := "SPAGETTY_TARGET=http://127.0.0.1:9\nSPAGETTY_TOKEN=tok\nSPAGETTY_NAME=web1\n"
	password := randToken(t)

	cases := []struct {
		name     string
		body     string
		want     string
		wantRefu bool
	}{
		{name: "defaults only", body: "SPAGETTY_ENDPOINT=wss://example.invalid/ws\n",
			want: "missing required SPAGETTY_TARGET, SPAGETTY_TOKEN, SPAGETTY_NAME, SPAGETTY_PASSWORD", wantRefu: true},
		{name: "no password", body: good, want: "missing required SPAGETTY_PASSWORD", wantRefu: true},
		{name: "empty value", body: good + "SPAGETTY_PASSWORD=\n", want: "missing required SPAGETTY_PASSWORD", wantRefu: true},
		{name: "not key=value", body: good + "this is not a setting\n", want: "expected KEY=VALUE", wantRefu: true},
		{name: "unterminated quote", body: good + `SPAGETTY_PASSWORD="abc` + "\n", want: "unterminated", wantRefu: true},
		{name: "short password", body: good + "SPAGETTY_PASSWORD=c2hvcnQ\n", want: "want 32", wantRefu: true},
		{name: "target is not http", body: "SPAGETTY_TARGET=ftp://127.0.0.1\nSPAGETTY_TOKEN=t\nSPAGETTY_NAME=w\nSPAGETTY_PASSWORD=" + password + "\n",
			want: "scheme must be http or https", wantRefu: true},
		{name: "endpoint scheme", body: "SPAGETTY_TARGET=http://127.0.0.1:9\nSPAGETTY_TOKEN=t\nSPAGETTY_NAME=w\nSPAGETTY_PASSWORD=" + password + "\nSPAGETTY_ENDPOINT=ftp://x/ws\n",
			want: "is not one of http, https, ws, wss", wantRefu: true},
		{name: "name has a space", body: "SPAGETTY_TARGET=http://127.0.0.1:9\nSPAGETTY_TOKEN=t\nSPAGETTY_NAME=web 1\nSPAGETTY_PASSWORD=" + password + "\n",
			want: "is not allowed", wantRefu: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := secretFile(t, filepath.Join(dir, "wrap.env"), tc.body)
			out, err := runWrap(t, wrapBin, dir, nil, "-env", path)
			if tc.wantRefu && err == nil {
				t.Fatalf("a misconfigured env file was accepted:\n%s", out)
			}
			if !tc.wantRefu && err != nil {
				t.Fatalf("a valid env file was refused: %v\n%s", err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output does not mention %q:\n%s", tc.want, out)
			}
		})
	}

	t.Run("env file missing everywhere", func(t *testing.T) {
		dir := t.TempDir() // no .env here
		out, err := runWrap(t, wrapBin, dir, nil, "-env", filepath.Join(dir, "absent.env"))
		if err == nil {
			t.Fatalf("a missing env file was accepted:\n%s", out)
		}
		if !strings.Contains(out, "absent.env (not found)") || !strings.Contains(out, ".env (not found)") {
			t.Fatalf("the refusal does not say which files were missing:\n%s", out)
		}
	})

	t.Run("the environment supplies what the file lacks", func(t *testing.T) {
		dir := t.TempDir()
		path := secretFile(t, filepath.Join(dir, "wrap.env"), good)
		out, err := runWrap(t, wrapBin, dir, []string{"SPAGETTY_PASSWORD=" + password}, "-env", path)
		if err != nil {
			t.Fatalf("a value from the environment was not used: %v\n%s", err, out)
		}
		if !strings.Contains(out, "SPAGETTY_PASSWORD: 43 characters (the environment)") {
			t.Fatalf("the password was not taken from the environment:\n%s", out)
		}
	})

	t.Run("the environment wins over the file", func(t *testing.T) {
		dir := t.TempDir()
		path := secretFile(t, filepath.Join(dir, "wrap.env"), good+"SPAGETTY_PASSWORD="+password+"\n")
		out, err := runWrap(t, wrapBin, dir, []string{"SPAGETTY_NAME=from-the-environment"}, "-env", path)
		if err != nil {
			t.Fatalf("unexpected refusal: %v\n%s", err, out)
		}
		if !strings.Contains(out, "SPAGETTY_NAME: from-the-environment (the environment)") {
			t.Fatalf("the environment did not win over the file:\n%s", out)
		}
	})

	t.Run(".env fills in what -env leaves out", func(t *testing.T) {
		dir := t.TempDir()
		secretFile(t, filepath.Join(dir, ".env"), "SPAGETTY_PASSWORD="+password+"\n")
		path := secretFile(t, filepath.Join(dir, "prod.env"), good)
		out, err := runWrap(t, wrapBin, dir, nil, "-env", path)
		if err != nil {
			t.Fatalf(".env was not consulted: %v\n%s", err, out)
		}
		if !strings.Contains(out, ".env line 1") {
			t.Fatalf("the password did not come from .env:\n%s", out)
		}
	})
}
