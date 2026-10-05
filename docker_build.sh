#!/usr/bin/env bash
# Build the mux image (the spagetti relay that mux.san.systems serves) and push
# it to the local registry, so the server can pull it.
#
# The gateway config — which carries the bearer tokens — is passed as a BuildKit
# secret: genembed turns it into Go source inside the build and it is compiled
# into the binary. Plaintext never enters the build context, a layer, or the
# server. ./cmd/spagetti-gateway/embedded_gen.go is generated in the image, and
# is git- and dockerignored so a local copy can never leak.
set -euo pipefail

CONFIG=${CONFIG:-.mux_config.json}
if [[ ! -f "$CONFIG" ]]; then
    echo "Error: config file '$CONFIG' not found (it holds the gateway bearer tokens)" >&2
    echo "Usage: CONFIG=path/to/gateway.json ./docker_build.sh" >&2
    echo "Create one with: go run ./cmd/spagetti-gateway -init $CONFIG   (then edit tokens/allow)" >&2
    exit 1
fi
chmod 600 "$CONFIG" 2>/dev/null || true

IMAGE_NAME=${IMAGE_NAME:-mux}
LOCAL_REGISTRY=${LOCAL_REGISTRY:-localhost:5010}
FULL_IMAGE_NAME="${LOCAL_REGISTRY}/${IMAGE_NAME}"
PLATFORM=${PLATFORM:-linux/amd64}   # the server is Intel; no native-arm build

echo "Building Docker image: ${IMAGE_NAME} (config secret: ${CONFIG})"
echo "Target registry: ${LOCAL_REGISTRY}   platform: ${PLATFORM}"

# Secret contents are invisible to BuildKit's cache key, so the hash busts it.
CONFIG_HASH=$(shasum -a 256 "$CONFIG" | cut -d' ' -f1)

docker buildx build \
  --progress=plain \
  --platform "${PLATFORM}" \
  --build-arg "CONFIG_HASH=${CONFIG_HASH}" \
  --secret "id=mux_config,src=${CONFIG}" \
  --load \
  -t "${IMAGE_NAME}" \
  .

echo "Tagging image for local registry: ${FULL_IMAGE_NAME}"
docker tag "${IMAGE_NAME}" "${FULL_IMAGE_NAME}"

echo "Pushing image to local registry: ${FULL_IMAGE_NAME}"
docker push "${FULL_IMAGE_NAME}"

echo "Successfully built and pushed ${FULL_IMAGE_NAME}"
echo "The gateway config (bearer tokens) is compiled into the binary."
echo "On the server:  docker compose up -d mux"
