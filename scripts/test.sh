#!/usr/bin/env bash

CNI_VERSION="${CNI_VERSION:-all}"
GOVERSION="$(go env GOVERSION | sed 's/go//')"
GOMODCACHE="$(go env GOMODCACHE)"

# CI runners don't always have this created yet
mkdir -p "${GOMODCACHE}"

root="$(git rev-parse --show-toplevel)"
export KUBECONFIG="${KUBECONFIG:-${root}/.kube/config}"
set -x

podman run --rm --privileged \
    -v "${GOMODCACHE}:/go/pkg/mod" \
    -v "${root}:/src" \
    -w /src \
    "${GO_IMAGE:-golang:$GOVERSION}" \
    go test -v "$@"
