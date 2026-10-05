// Command spagetti-gateway runs the public relay: servers dial out to it, clients
// connect to it, and it splices opaque channels between them.
//
//	spagetti-gateway -init /etc/spagetti/gateway.json   # write a starter config with fresh tokens
//	spagetti-gateway -config /etc/spagetti/gateway.json -addr :8080
//	spagetti-gateway -config /etc/spagetti/gateway.json -check   # validate, report, do not listen
//
// An image built by docker_build.sh carries its configuration — including the
// bearer tokens — compiled in (see cmd/genembed and the Dockerfile), so such a
// build needs no -config and no file on the host.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sannysanoff/spagetti/gateway"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	addr := flag.String("addr", ":8080", "listen address")
	cfgPath := flag.String("config", "", "gateway config file (JSON); falls back to the embedded config when one was built in")
	initPath := flag.String("init", "", "write a starter config with fresh tokens to this path and exit")
	check := flag.Bool("check", false, "load the configuration, report what it admits, and exit without listening")
	flag.Parse()

	if *initPath != "" {
		if err := writeStarter(*initPath); err != nil {
			log.Fatalf("spagetti-gateway: %v", err)
		}
		return
	}

	cfg, source, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
	cfg.Logf = log.Printf
	g, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
	if *check {
		// Loading the config also proves every token resolves: a role, an allow
		// list and a secret of usable length. The image build runs this, so a
		// config that admits nobody cannot become a running relay.
		log.Printf("spagetti-gateway: config ok from %s: %s", source, tokenSummary(cfg.Tokens))
		g.Close()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("spagetti-gateway: %s; %s", source, tokenSummary(cfg.Tokens))
	if err := g.Run(ctx, *addr); err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
}

// loadConfig resolves the configuration: an explicit file wins, then whatever
// was compiled into the binary, then nothing — which is a loud failure rather
// than a relay that quietly admits nobody.
func loadConfig(path string) (gateway.Config, string, error) {
	if path != "" {
		cfg, err := gateway.LoadConfigFile(path)
		return cfg, path, err
	}
	raw, err := embeddedConfig()
	if err != nil {
		return gateway.Config{}, "", err
	}
	if len(raw) == 0 {
		return gateway.Config{}, "", fmt.Errorf(
			"no configuration: pass -config, or build an image with docker_build.sh, which compiles one in")
	}
	cfg, err := gateway.LoadConfig(raw)
	return cfg, "the embedded config", err
}

// embeddedConfig decodes the configuration compiled in at image build time. It
// is empty in a plain `go build`.
func embeddedConfig() ([]byte, error) {
	chunks := embeddedChunks()
	if len(chunks) == 0 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(strings.Join(chunks, ""))
}

// tokenSummary describes what the gateway admits without revealing any secret.
func tokenSummary(tokens []gateway.Token) string {
	parts := make([]string, 0, len(tokens))
	for _, t := range tokens {
		source := "inline"
		switch {
		case t.TokenFile != "":
			source = "file"
		case t.TokenEnv != "":
			source = "env:" + t.TokenEnv
		}
		parts = append(parts, fmt.Sprintf("%s %q allow=%v (%s)", t.Kind, t.Name, t.Allow, source))
	}
	return fmt.Sprintf("%d token(s): %s", len(tokens), strings.Join(parts, ", "))
}

func writeStarter(path string) error {
	server, err := token()
	if err != nil {
		return err
	}
	client, err := token()
	if err != nil {
		return err
	}
	cfg := map[string]any{
		"tokens": []map[string]any{
			{"name": "example-server", "kind": "server", "token": server, "allow": []string{"example"}},
			{"name": "example-client", "kind": "client", "token": client, "allow": []string{"*"}},
		},
		"max_channels_per_client": 64,
		"ping_interval_sec":       25,
		"idle_timeout_sec":        90,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  server token: %s (allow: [example])\n  client token: %s (allow: [*])\n", path, server, client)
	return nil
}

func token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
