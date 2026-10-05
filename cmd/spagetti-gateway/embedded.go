package main

// Placeholder so a plain `go build` of this repo compiles: it carries no
// configuration, and the gateway then demands -config rather than starting deaf.
//
// cmd/genembed writes the real thing to embedded_gen.go during an image build
// (see Dockerfile and docker_build.sh): the BuildKit secret that holds the
// gateway config — the bearer tokens — becomes base64 chunks here and is
// compiled into the binary. Plaintext config lands in no layer, and nothing has
// to exist on the host at runtime. embedded_gen.go is git- and dockerignored, so
// a locally generated copy can never be committed or copied into a build.

func embeddedChunks() []string { return nil }
