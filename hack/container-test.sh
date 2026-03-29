#!/usr/bin/env bash

LABEL_FILTER="${LABEL_FILTER:-e2e && !k8s}"
GOVERSION="$(go env GOVERSION | sed 's/go//')"
GOMODCACHE="$(go env GOMODCACHE)"
PODMAN="${PODMAN:-podman}"

# CI runners don't always have this created yet
mkdir -p "${GOMODCACHE}"

root="$(git rev-parse --show-toplevel)"

set -x

$PODMAN run --rm --privileged \
    -v "$GOMODCACHE:/go/pkg/mod" \
    -v "$root:/src" \
    -w /src \
    "${GO_IMAGE:-golang:$GOVERSION}" \
    go test -v ./... -ginkgo.label-filter="$LABEL_FILTER"
