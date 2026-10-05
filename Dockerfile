# syntax=docker/dockerfile:1.7
# The mux image: the spagetti relay (gateway) that mux.san.systems serves.
# Built by docker_build.sh, which passes the gateway config — the bearer tokens
# — as a BuildKit secret. genembed turns it into Go source and it is COMPILED
# INTO the binary: plaintext never lands in a layer, and nothing has to exist on
# the server at runtime.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# CONFIG_HASH busts this layer's cache when the secret changes: BuildKit's cache
# key cannot see secret contents.
ARG CONFIG_HASH
RUN --mount=type=secret,id=mux_config,target=/run/secrets/mux_config \
    rm ./cmd/spagetti-gateway/embedded.go && \
    go run ./cmd/genembed /run/secrets/mux_config ./cmd/spagetti-gateway/embedded_gen.go && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/spagetti-gateway ./cmd/spagetti-gateway && \
    /out/spagetti-gateway -check

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10002 -H mux
COPY --from=build /out/spagetti-gateway /usr/local/bin/spagetti-gateway
USER mux
EXPOSE 8080
# No -config: the embedded configuration is what this image carries.
ENTRYPOINT ["/usr/local/bin/spagetti-gateway"]
