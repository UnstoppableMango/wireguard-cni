#!/usr/bin/env bash

CNI_VERSION="${CNI_VERSION:-all}"
LABEL_FILTER="${LABEL_FILTER:-!e2e}"

root="$(git rev-parse --show-toplevel)"

if [[ "$CNI_VERSION" != "all" ]]; then
    LABEL_FILTER="${LABEL_FILTER} && ${CNI_VERSION}"
fi

GOVERSION="$(go env GOVERSION | sed 's/go//')"
GOMODCACHE="$(go env GOMODCACHE)"

# CI runners don't always have this created yet
mkdir -p "${GOMODCACHE}"

set -x

podman run --rm --privileged \
    -v "${GOMODCACHE}:/go/pkg/mod" \
    -v "${root}:/src" \
    -w /src \
    "${GO_IMAGE:-golang:$GOVERSION}" \
    go test -v -ginkgo.label-filter="${LABEL_FILTER}" ./...
