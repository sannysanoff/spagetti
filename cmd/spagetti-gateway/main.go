// Command spagetti-gateway runs the public relay: servers dial out to it, clients
// connect to it, and it splices opaque channels between them.
//
//	spagetti-gateway -init /etc/spagetti/gateway.json   # write a starter config with fresh tokens
//	spagetti-gateway -config /etc/spagetti/gateway.json -addr :8080
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
	"syscall"

	"github.com/sannysanoff/spagetti/gateway"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	addr := flag.String("addr", ":8080", "listen address")
	cfgPath := flag.String("config", "", "gateway config file (JSON)")
	initPath := flag.String("init", "", "write a starter config with fresh tokens to this path and exit")
	flag.Parse()

	if *initPath != "" {
		if err := writeStarter(*initPath); err != nil {
			log.Fatalf("spagetti-gateway: %v", err)
		}
		return
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "spagetti-gateway: -config is required (or -init to create one)")
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := gateway.LoadConfigFile(*cfgPath)
	if err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
	cfg.Logf = log.Printf
	g, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := g.Run(ctx, *addr); err != nil {
		log.Fatalf("spagetti-gateway: %v", err)
	}
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
