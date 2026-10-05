// Command spagetti-call is a small client for humans: it lists the gateway
// directory, pins a server's files, and makes requests through end-to-end
// channels. It is also what the end-to-end binary test drives.
//
//	spagetti-call -gateway ws://127.0.0.1:8080/ws -token-env SPAGETTI_CLIENT_TOKEN list
//	spagetti-call -conf ~/.spagetti pin -server web1 -pub srv/identity.pub -password srv/access.password
//	spagetti-call ... get web1 /whoami
//	spagetti-call ... post web1 /echo/body hello
//	spagetti-call ... sse web1 /events
//	spagetti-call ... ws web1 /ws hello
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/client"
	"github.com/sannysanoff/spagetti/conf"
)

func main() {
	fs := flag.NewFlagSet("spagetti-call", flag.ExitOnError)
	gatewayURL := fs.String("gateway", os.Getenv("SPAGETTI_GATEWAY"), "gateway websocket url, e.g. ws://127.0.0.1:8080/ws")
	token := fs.String("token", "", "gateway bearer token")
	tokenFile := fs.String("token-file", "", "file holding the gateway bearer token")
	tokenEnv := fs.String("token-env", "SPAGETTI_CLIENT_TOKEN", "environment variable holding the gateway bearer token")
	confDir := fs.String("conf", conf.Dir(), "spagetti configuration directory")
	clientID := fs.String("client-id", "", "caller label (defaults to the device key fingerprint)")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: spagetti-call [flags] <list|pin|get|post|sse|ws> [args]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	sub := "list"
	if len(rest) > 0 {
		sub = rest[0]
		rest = rest[1:]
	}
	subFS := flag.NewFlagSet(sub, flag.ExitOnError)
	pinServer := subFS.String("server", "", "server id (pin)")
	pinPub := subFS.String("pub", "", "server identity.pub file to pin")
	pinPassword := subFS.String("password", "", "server access.password file to pin")
	if err := subFS.Parse(rest); err != nil {
		os.Exit(2)
	}
	args := subFS.Args()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if sub == "pin" {
		if *pinServer == "" || *pinPub == "" || *pinPassword == "" {
			fatal("pin needs -server, -pub and -password")
		}
		pub, err := conf.LoadPub(*pinPub)
		if err != nil {
			fatal("%v", err)
		}
		pw, err := conf.LoadPassword(*pinPassword)
		if err != nil {
			fatal("%v", err)
		}
		peer, err := conf.SavePeer(*confDir, *pinServer, pub, pw)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Printf("pinned %s: key %s, password %s\n", peer.ServerID, peer.PubFile, peer.PasswordFile)
		return
	}
	if *gatewayURL == "" {
		fatal("need -gateway ws://host:port/ws (or SPAGETTI_GATEWAY)")
	}
	c, err := client.New(client.Options{
		GatewayURL: *gatewayURL,
		Token:      *token,
		TokenFile:  *tokenFile,
		TokenEnv:   *tokenEnv,
		ConfDir:    *confDir,
		ClientID:   *clientID,
		Logf:       func(f string, a ...any) { fmt.Fprintf(os.Stderr, "spagetti: "+f+"\n", a...) },
	})
	if err != nil {
		fatal("%v", err)
	}
	defer c.Close()

	switch sub {
	case "list":
		entries, err := c.ListServers(ctx)
		if err != nil {
			fatal("%v", err)
		}
		if len(entries) == 0 {
			fmt.Println("no servers registered")
			return
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\tonline=%v\tchannels=%d\t%s\n", e.ServerID, e.Name, e.Online, e.Channels, e.Fingerprint)
		}
	case "get", "post":
		if len(args) < 2 {
			fatal("usage: spagetti-call [flags] %s <server> <path> [body]", sub)
		}
		var body io.Reader
		if len(args) > 2 {
			body = strings.NewReader(strings.Join(args[2:], " "))
		}
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(sub), "http://"+args[0]+args[1], body)
		if err != nil {
			fatal("%v", err)
		}
		resp, err := c.HTTPClient(args[0]).Do(req)
		if err != nil {
			fatal("%v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("HTTP %d\n%s", resp.StatusCode, string(b))
		if resp.StatusCode >= 400 {
			os.Exit(1)
		}
	case "sse":
		if len(args) < 2 {
			fatal("usage: spagetti-call [flags] sse <server> <path>")
		}
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+args[0]+args[1], nil)
		resp, err := c.HTTPClient(args[0]).Do(req)
		if err != nil {
			fatal("%v", err)
		}
		defer resp.Body.Close()
		var first time.Duration
		total := 0
		buf := make([]byte, 4096)
		for {
			k, err := resp.Body.Read(buf)
			if k > 0 {
				if first == 0 {
					first = time.Since(start)
				}
				total += k
				os.Stdout.Write(buf[:k])
			}
			if err != nil {
				break
			}
		}
		fmt.Fprintf(os.Stderr, "\nfirst chunk after %s, %d bytes total\n", first.Round(time.Millisecond), total)
	case "ws":
		if len(args) < 2 {
			fatal("usage: spagetti-call [flags] ws <server> <path> [message]")
		}
		ws, err := c.DialWS(ctx, args[0], "ws://"+args[0]+args[1], nil)
		if err != nil {
			fatal("%v", err)
		}
		defer ws.Close()
		msg := "ping"
		if len(args) > 2 {
			msg = strings.Join(args[2:], " ")
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			fatal("%v", err)
		}
		ws.SetReadDeadline(time.Now().Add(*timeout))
		_, b, err := ws.ReadMessage()
		if err != nil {
			fatal("%v", err)
		}
		fmt.Printf("websocket echo: %s\n", b)
	default:
		fatal("unknown command %q (list|pin|get|post|sse|ws)", sub)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "spagetti-call: "+format+"\n", args...)
	os.Exit(1)
}
