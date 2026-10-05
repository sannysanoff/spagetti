# spagetti

Spagetti is a small Go library plus a relay for reaching servers that cannot be
reached. A server dials *out* to a public gateway from inside private
infrastructure; a client dials the same gateway; the gateway splices an
end-to-end encrypted channel between the two and forwards opaque records. Servers
authorise their callers with a public/private-key challenge bound to an access
password. The gateway routes; it cannot read.

Written for one mode of use: you already have an `http.Handler`, and spagetti
makes it reachable from anywhere without an inbound port, a VPN, or a
certificate authority.

```
your http.Handler ── server.Serve ──▶ gateway ◀── client ── your http.Client
                       (dials out)      (relay)     (dials out)
```

## What the gateway can and cannot do

This is the whole point of the design, so it is worth being exact.

**It cannot read, alter or forge channel content.** Every channel carries a
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake between the caller and the
server. The caller already holds the server's public key and passes it as the
handshake pre-message, so the responder it talks to is that key's holder or
nobody; the access password is the Noise pre-shared key, mixed into the chaining
key before the two transport cipher states are derived. A channel record that
fails authentication is never delivered: it fails the channel. The route label
(server id, channel id, epoch) is bound into the handshake prologue, so the relay
can neither rename nor splice a channel, and replayed records do not decrypt
because the responder mints a fresh ephemeral every handshake.

**It does see routing metadata**: which server ids are online, which caller
opened which channel, when, and how many bytes crossed. That is unavoidable —
somebody has to route — and it is stated rather than implied. If the relay must
not learn even that, spagetti is not the tool.

**It cannot hold keys, structurally.** The `gateway` package's dependency graph
contains no crypto code of its own: no `flynn/noise`, no `x/crypto`, and no
direct import of any stdlib crypto package. Its whole first-party footprint is
`wire` and itself, and the only packages its binary links from this module are
`spagetti/wire`, `spagetti/gateway`, `spagetti/cmd/spagetti-gateway`. (The graph
does contain `crypto/tls` and friends, pulled in by `net/http`; that code is
unreachable from the relay's logic, which is why the test bans stdlib crypto as a
*direct* import and the handshake, key and key-file packages transitively.) That
is asserted by `TestGatewayCannotHoldKeys` against `go list -deps`, not by
convention.

Admission is a bearer token. Two token roles — `server` and `client` — and each
token names the server ids it may register or reach. The token is a door key, not
a content key.

## Quick start

Four binaries: `spagetti-gateway` (run it where both sides can reach it),
`spagetti-wrap` (publish a webserver you already have), `examples/echo-server`
(a wrapped server, for testing), `spagetti-call` (a client for humans).

```sh
# 1. the relay
go build -o bin/ ./cmd/spagetti-gateway
./bin/spagetti-gateway -init /etc/spagetti/gateway.json     # prints two fresh tokens
./bin/spagetti-gateway -config /etc/spagetti/gateway.json -addr :8080

# 2. the server, from the private network
SPAGETTI_CONF_DIR=~/.spagetti ./bin/echo-server \
    -gateway ws://gateway.internal:8080/ws -token "$SERVER_TOKEN" -id web1
# first run generates the server's keypair and access password and prints the
# exact copy commands for step 3.

# 3. the client, anywhere
./bin/spagetti-call -gateway ws://gateway.internal:8080/ws -token "$CLIENT_TOKEN" \
    pin -server web1 -pub ~/.spagetti/servers/web1/identity.pub \
        -password ~/.spagetti/servers/web1/access.password
./bin/spagetti-call ... list
./bin/spagetti-call ... get web1 /whoami
```

The pin step is the human part of the protocol, and it is deliberately file-shaped:
`identity.pub` is the server's public key, `access.password` is a 32-byte secret
used directly as the Noise PSK. Copy both to the client and nothing else is
needed. `SPAGETTI_CONF_DIR` defaults to `~/.spagetti`; the layout is documented in
`conf/`.

## Publishing a webserver you already have

`spagetti-wrap` puts a target webserver behind the gateway by reverse-proxying it,
so a service that knows nothing about spagetti needs no change at all — it sees
ordinary requests and can stream or speak websockets. The target and every
credential come from an env file; the command line takes nothing but that file:

```sh
go build -o bin/ ./cmd/spagetti-wrap
./bin/spagetti-wrap -env /etc/spagetti/web1.env     # .env is the default
```

```
# /etc/spagetti/web1.env — chmod 600, it holds the token and the password
SPAGETTY_TARGET=http://127.0.0.1:9000            # required: the webserver to expose
SPAGETTY_NAME=web1                               # required: the name clients ask for
SPAGETTY_TOKEN=...                               # required: the gateway's server token
SPAGETTY_PASSWORD=...                            # required: base64url of 32 bytes
#   mint one with: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
SPAGETTY_ENDPOINT=https://mux.san.systems/ws     # optional, this is the default
SPAGETTY_KEYS=.spagetti-keys                     # optional: keypair cache file
```

Values are resolved from the process environment first, then from the file named
with `-env`, then from `.env`. Every file that exists is read and each source only
fills in what is still missing, so an exported variable overrides a file without
editing it. A required key that no source supplies refuses to start instead of
guessing. The keypair is minted into `SPAGETTY_KEYS` on the first run and reused
afterwards; `<cache>.pub` and `<cache>.password` are written next to it, and those
two files are what a client pins.

It logs the connection to the gateway, and one line per forwarded request —
timestamp, verb, path — at request time, with nothing about responses.

## Using it as a library

The module is `github.com/sannysanoff/spagetti`:

```sh
go get github.com/sannysanoff/spagetti
```

Server side — wrap an existing handler:

```go
handler := http.NewServeMux()
handler.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
    peer, _ := server.PeerFromContext(r.Context())
    fmt.Fprintf(w, "hello %s (%s)\n", peer.ID, peer.Fingerprint)
})

server.Serve(ctx, server.Options{
    GatewayURL: "ws://gateway.internal:8080/ws",
    Token:      os.Getenv("SPAGETTI_SERVER_TOKEN"),
    ServerID:   "web1",
    Handler:    handler,
    AllowClient: func(p server.Peer) bool { return allowed(p.Fingerprint) }, // optional
})
```

Client side — a channel is a `net.Conn`, so `net/http` is the RPC protocol:

```go
c, _ := client.New(client.Options{
    GatewayURL: "ws://gateway.internal:8080/ws",
    Token:      os.Getenv("SPAGETTI_CLIENT_TOKEN"),
})
defer c.Close()

hc := c.HTTPClient("web1")                 // the URL host is the server id
resp, _ := hc.Get("http://web1/whoami")    // REST, streaming, SSE: all ordinary

ws, _ := c.DialWS(ctx, "web1", "ws://web1/socket", nil)  // websockets too
conn, _ := c.Dial(ctx, "web1")             // or the raw encrypted net.Conn
```

There is no spagetti RPC layer to learn: a channel is an authenticated byte
stream, and HTTP, SSE and websocket upgrades ride through it unchanged. The
wrapped handler sees normal `http.Request`s, can keep-alive, can hijack.

It is a full `net.Conn`, deadlines included, and that matters more than it
sounds: `net/http` keeps a background read on every connection and aborts it by
reactivating a read deadline in the past — after every response, and again when a
handler hijacks the connection for a websocket upgrade. A conn whose deadline
could not interrupt a read that was already blocked would leave the server's
connection goroutine stuck and the request or upgrade hanging. Deadlines on a
channel are per direction and reactivatable, and a stalled writer is bounded by
the write deadline rather than blocking forever on a full outbound queue.

## Authentication, in three layers

Admission to the gateway is a bearer token, scoped per role and per server id.
That decides who may ask for a route; it decides nothing about content.

Per channel, the caller proves two things. It proves it holds the *access
password* — the server's answer to the handshake is encrypted under keys that
include the PSK, so a wrong password fails on the server's challenge response,
before a single application byte moves. It also identifies itself with its own
device key: clients mint a keypair on first use, and the server sees that key as
the authenticated peer. The password bootstraps the relationship; the device key
is what you revoke per device later.

Then, optionally, `AllowClient` decides whether this caller may use the channel at
all. A refusal travels back as an authenticated verdict, so the caller's `Dial`
fails with `not_allowed` rather than discovering it on first use.

**Periodic re-authorisation** is epoch-based rather than timer-based. A channel
may not be opened with an epoch older than the current one (plus one for clock
skew), and no channel outlives `MaxChannelLifetime`. Idle channels therefore cost
nothing, and a revoked password stops working within one epoch — fifteen minutes
by default. Nothing here invents a lease protocol.

## Knowing the limits

Real limits, stated so they are not discovered in production:

**No per-channel flow control.** A consumer that stalls past
`MaxChannelBuffer` (4 MiB per channel by default; `MaxOutBuffer` on the relay) has
its channel dropped with `overload`. A slow SSE reader on a long-lived stream will
eventually be cut rather than back-pressured through a multiplexed tunnel.

**The relay is stateful and single-instance in this version.** Routing lives in
memory, so there is no failover: a caller retries against another gateway
address, a server reconnects to whichever gateway it is configured with. Server
reconnect with backoff is implemented and tested; gateway HA is not. What is
tested is that a gateway which goes away takes its peers with it: sessions are
torn down whether the shutdown came from a cancelled context or from the listener
dying under it, so a server finds out in milliseconds and keeps retrying rather
than sitting on a socket nobody is reading. A peer left on a dead relay would
only notice when its idle timeout expired.

**The relay is in the path and can deny service.** It can drop, delay or stall
traffic; it cannot read or alter it. Availability is trusted to the relay,
confidentiality and integrity are not.

**Metadata is visible to the relay.** See above. The caller's label is also
announced to the gateway in the clear, as routing metadata; inside the channel
nothing is.

**Replay protection is bounded.** Nonces are remembered for a two-minute window
(`ReplayWindow`) and the cache is capped; the window is what makes a captured
handshake useless, not an unbounded log.

## What is verified, and how

`go test ./...` runs the whole thing against real sockets: a real gateway, a real
wrapped server, a real client, and a hostile relay that sits in the middle.

The adversarial suite is the part that matters. `TestRelaySeesCiphertextOnly`
records every byte that crosses the relay and asserts that neither request nor
response plaintext, nor the password, nor the pinned key appears in it — with a
positive control that the routing label *does* appear, so the negative result is
not an artefact of an empty recording. `TestSubstitutedHandshakeFailsClosed` has
the relay swallow the handshake and answer with its own bytes, and asserts the
caller fails with `auth_failed` and the handler is never reached.
`TestCapturedHandshakeCannotBeReplayed` and `TestReusedNonceRejected` cover both
replay shapes. `TestRecordTamperingIsNotDelivered` and
`TestDuplicatedRecordIsRejected` flip and duplicate records and assert the
handler sees nothing. Token scope, role mismatch and missing tokens are refused.
`TestBinariesEndToEnd` builds and runs the three commands and drives them like an
operator would, including SSE arrival timing and a websocket echo inside the
tunnel.

Two areas earn their own coverage because they are where silent hangs used to
live. `TestGatewayShutdownDisconnectsServer`, `TestListenerCloseDisconnectsPeers`
and `TestServerReconnectsAfterGatewayRestart` assert that a relay which dies —
by cancelled context or by its listener being closed underneath it — disconnects
its peers and that a server re-registers with the replacement gateway.
`TestHijackSurvivesBackgroundRead`, `TestRequestResponseCyclesDoNotStall`,
`TestConcurrentChannels` and the `tunnel` deadline tests assert the `net.Conn`
contract that net/http leans on: a read deadline, including one set on a read
that is already blocked, interrupts the read, a queued record still beats an
expired deadline, and clearing the deadline resumes blocking.

Run it with `-race`; the multiplexed tunnel is where races would live.

## Layout

`wire` is the frame format — the only thing the relay parses. `tunnel` carries a
websocket connection and multiplexes sequence-checked record streams. `e2e` is the
handshake and the encrypted `net.Conn`. `conf` owns the files on disk. `client`
and `server` are the library. `gateway` is the relay, and depends only on `wire`.
