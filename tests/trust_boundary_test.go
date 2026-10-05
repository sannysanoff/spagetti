package tests

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenTransitively must not appear anywhere in the relay's dependency
// graph. These are the handshake, the extended crypto library and the
// first-party packages that own keys: if any of them is reachable from the
// gateway, the gateway can hold keys and "the gateway cannot reach content"
// stops being structural.
var forbiddenTransitively = []string{
	"github.com/flynn/noise",
	"golang.org/x/crypto",
	"github.com/sannysanoff/spagetti/e2e",
	"github.com/sannysanoff/spagetti/conf",
	"github.com/sannysanoff/spagetti/tunnel",
	"github.com/sannysanoff/spagetti/client",
	"github.com/sannysanoff/spagetti/server",
}

// forbiddenDirectly are stdlib crypto packages that the gateway's own files
// must not import. They cannot be banned transitively: net/http pulls in
// crypto/tls, which pulls in most of the standard library's crypto, and that
// code is unreachable from the relay's logic. A direct import, on the other
// hand, is the gateway reaching for key material itself.
var forbiddenDirectly = []string{
	"crypto/aes",
	"crypto/cipher",
	"crypto/dsa",
	"crypto/ecdh",
	"crypto/ecdsa",
	"crypto/ed25519",
	"crypto/hkdf",
	"crypto/rsa",
	"crypto/tls",
}

// modulePrefix is this module's import path; it must agree with go.mod.
const modulePrefix = "github.com/sannysanoff/spagetti/"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("go toolchain not on PATH")
		}
		cmd := exec.Command("go", "env", "GOMOD")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err == nil {
			mod := strings.TrimSpace(string(out))
			if mod != "" && mod != "/dev/null" {
				return filepath.Dir(mod)
			}
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate go.mod above the test directory")
	return ""
}

func goList(t *testing.T, root string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.Fields(string(out))
}

// TestGatewayCannotHoldKeys is the compile-time half of the trust boundary: the
// relay binary's dependency graph contains no handshake, no key type and no key
// file handling.
func TestGatewayCannotHoldKeys(t *testing.T) {
	root := moduleRoot(t)
	targets := []string{"./gateway", "./cmd/spagetti-gateway"}

	deps := goList(t, root, "list", "-deps", targets[0], targets[1])
	if len(deps) < 10 {
		t.Fatalf("suspiciously small dependency list (%d entries)", len(deps))
	}
	seenWire := false
	for _, d := range deps {
		if d == "github.com/sannysanoff/spagetti/wire" {
			seenWire = true
		}
		for _, bad := range forbiddenTransitively {
			if d == bad || strings.HasPrefix(d, bad+"/") {
				t.Errorf("the gateway depends on %s: the trust boundary is broken", d)
			}
		}
	}
	if !seenWire {
		t.Fatal("the gateway does not depend on spagetti/wire: the listing is not the real graph")
	}

	// The gateway's own direct imports: a direct reach for key material is the
	// gateway doing crypto itself, whatever the standard library does below it.
	imports := goList(t, root, "list", "-f", "{{join .Imports \"\\n\"}}", "./gateway", "./cmd/spagetti-gateway")
	var own []string
	for _, d := range deps {
		if strings.HasPrefix(d, modulePrefix) {
			own = append(own, d)
		}
	}
	for _, imp := range imports {
		for _, bad := range forbiddenDirectly {
			if imp == bad {
				t.Errorf("the gateway imports %s directly: the trust boundary is broken", imp)
			}
		}
	}
	t.Logf("gateway: %d packages in the graph, none crypto; first-party: %s",
		len(deps), strings.Join(own, ", "))
}

// TestClientAndServerDoDependOnTheCryptoLayer is the control: the boundary test
// above would pass trivially if the crypto packages did not exist at all.
func TestClientAndServerDoDependOnTheCryptoLayer(t *testing.T) {
	root := moduleRoot(t)
	deps := goList(t, root, "list", "-deps", "./client", "./server")
	found := map[string]bool{}
	for _, d := range deps {
		found[d] = true
	}
	for _, want := range []string{
		"github.com/sannysanoff/spagetti/e2e",
		"github.com/sannysanoff/spagetti/conf",
		"github.com/sannysanoff/spagetti/tunnel",
		"github.com/sannysanoff/spagetti/wire",
		"github.com/flynn/noise",
	} {
		if !found[want] {
			t.Errorf("the client/server side does not depend on %s; the boundary test proves nothing", want)
		}
	}
}
