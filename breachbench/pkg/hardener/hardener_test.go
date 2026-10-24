package hardener

import (
	"strings"
	"testing"
)

func TestAnalyzeAndRenderHardenedDockerfile(t *testing.T) {
	sampleUbuntuDockerfile := `
FROM ubuntu:22.04
ENV APP_ENV=production
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ./server /rootfs/usr/bin/server
EXPOSE 8080
ENTRYPOINT ["/usr/bin/server"]
CMD ["--port", "8080"]
`

	analysis := AnalyzeDockerfileDeterministic(sampleUbuntuDockerfile)
	if analysis.OriginalBaseImage != "ubuntu:22.04" {
		t.Fatalf("expected OriginalBaseImage ubuntu:22.04, got %s", analysis.OriginalBaseImage)
	}
	if len(analysis.AptPackages) != 3 {
		t.Fatalf("expected 3 apt packages, got %v", analysis.AptPackages)
	}

	rendered, err := RenderHardenedDockerfile(analysis)
	if err != nil {
		t.Fatalf("RenderHardenedDockerfile failed: %v", err)
	}

	requiredSnippets := []string{
		"FROM ubuntu:22.04 AS builder",
		"FROM scratch",
		"COPY --from=builder --chown=53111:53111 /rootfs/ /",
		"USER 53111:53111",
		"/rootfs/sbom.json",
		`ENTRYPOINT ["/usr/bin/server"]`,
		`CMD ["--port", "8080"]`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(rendered, snippet) {
			t.Errorf("expected rendered Dockerfile to contain %q, got:\n%s", snippet, rendered)
		}
	}
}

func TestIsUnhardenedDistroDockerfile(t *testing.T) {
	multiStageDistro := `
ARG BASE_IMG=python:3.13-slim-bookworm
FROM ${BASE_IMG} AS base
FROM base AS runtime
CMD ["python3"]
`
	ok, base := IsUnhardenedDistroDockerfile(multiStageDistro)
	if !ok || base != "python:3.13-slim-bookworm" {
		t.Fatalf("expected match python:3.13-slim-bookworm, got ok=%v base=%q", ok, base)
	}

	alpineImg := `
FROM node:20-alpine AS builder
FROM nginx:stable-alpine
`
	if ok, _ := IsUnhardenedDistroDockerfile(alpineImg); ok {
		t.Fatalf("expected alpine image to be excluded")
	}
}
