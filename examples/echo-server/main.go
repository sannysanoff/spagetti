// Command echo-server is a spagetti server: an ordinary http.Handler wrapped by
// spagetti.Serve. It exposes endpoints that make the tunnel observable — echo,
// request bodies, SSE streaming, a websocket echo and a large response.
//
//	spagetti-call ... get echo /echo
//	spagetti-call ... sse echo /events
//	spagetti-call ... ws  echo /ws
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/server"
)

func main() {
	gatewayURL := flag.String("gateway", "ws://127.0.0.1:8080/ws", "gateway websocket url")
	token := flag.String("token", "", "gateway bearer token")
	tokenEnv := flag.String("token-env", "SPAGETTI_SERVER_TOKEN", "environment variable holding the token")
	id := flag.String("id", "echo", "server id clients ask for")
	name := flag.String("name", "", "human name for the directory")
	tags := flag.String("tags", "", "comma separated tags")
	confDir := flag.String("conf", conf.Dir(), "spagetti configuration directory")
	epoch := flag.Duration("epoch", 15*time.Minute, "channel re-authentication epoch")
	lifetime := flag.Duration("channel-lifetime", time.Hour, "maximum lifetime of one channel")
	maxChannels := flag.Int("max-channels", 64, "concurrent channels")
	flag.Parse()

	var tagList []string
	for _, t := range strings.Split(*tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tagList = append(tagList, t)
		}
	}

	opts := server.Options{
		GatewayURL:         *gatewayURL,
		Token:              *token,
		TokenEnv:           *tokenEnv,
		ServerID:           *id,
		Name:               *name,
		Tags:               tagList,
		ConfDir:            *confDir,
		Handler:            handler(),
		MaxChannels:        *maxChannels,
		EpochLifetime:      *epoch,
		MaxChannelLifetime: *lifetime,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Serve(ctx, opts); err != nil {
		log.Fatalf("echo-server: %v", err)
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// The caller is authenticated by the spagetti challenge, not by the Origin
	// header, so origin checking is meaningless here.
	CheckOrigin: func(*http.Request) bool { return true },
}

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		peer, _ := server.PeerFromContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{
			"id":          peer.ID,
			"fingerprint": peer.Fingerprint,
			"public_key":  hex.EncodeToString(peer.PubKey),
		})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		peer, ok := server.PeerFromContext(r.Context())
		hdrs := map[string]string{}
		for k, v := range r.Header {
			hdrs[k] = strings.Join(v, ",")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"method":        r.Method,
			"path":          r.URL.Path,
			"query":         r.URL.RawQuery,
			"host":          r.Host,
			"headers":       hdrs,
			"authenticated": ok,
			"peer":          peer.ID,
			"fingerprint":   peer.Fingerprint,
		})
	})
	mux.HandleFunc("/echo/body", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(b)
		json.NewEncoder(w).Encode(map[string]any{
			"bytes":  len(b),
			"sha256": hex.EncodeToString(sum[:]),
			"echo":   len(b) <= 256,
			"body":   string(b),
		})
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		n := 5
		if v := r.URL.Query().Get("n"); v != "" {
			if k, err := strconv.Atoi(v); err == nil && k > 0 {
				n = k
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "data: event %d at %s\n\n", i, time.Now().Format(time.RFC3339Nano))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n := 1 << 20
		if v := r.URL.Query().Get("n"); v != "" {
			if k, err := strconv.Atoi(v); err == nil && k > 0 {
				n = k
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 32<<10)
		for i := range chunk {
			chunk[i] = byte('a' + i%26)
		}
		for written := 0; written < n; {
			k := len(chunk)
			if n-written < k {
				k = n - written
			}
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			written += k
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			mt, b, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := ws.WriteMessage(mt, append([]byte("echo: "), b...)); err != nil {
				return
			}
		}
	})
	return mux
}
