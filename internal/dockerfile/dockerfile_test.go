package dockerfile_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"BreachBench/internal/dockerfile"
	"BreachBench/internal/hardening"
)

func TestBadgeAPIStaticImageStageTrace(t *testing.T) {
	recipe := `FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /badge-api ./cmd/badge-api

FROM zendis/static:1.0.0-rc.8-minimal
COPY --from=build /badge-api /badge-api
CMD ["/badge-api", "serve", "--port", "8080"]
`
	report, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if report.RuntimeBase != "zendis/static:1.0.0-rc.8-minimal" {
		t.Fatalf("RuntimeBase = %q, want zendis/static:1.0.0-rc.8-minimal", report.RuntimeBase)
	}
	if report.StartupDeclaration != `CMD ["/badge-api","serve","--port","8080"]` {
		t.Fatalf("StartupDeclaration = %q", report.StartupDeclaration)
	}
	if report.ExecutableTrace.Executable != "/badge-api" {
		t.Fatalf("Executable = %q, want /badge-api", report.ExecutableTrace.Executable)
	}
	if report.ExecutableTrace.OriginType != "copied-from-stage" {
		t.Fatalf("OriginType = %q, want copied-from-stage", report.ExecutableTrace.OriginType)
	}
	if report.ExecutableTrace.OriginSummary != "Copied from the Go build stage" {
		t.Fatalf("OriginSummary = %q, want 'Copied from the Go build stage'", report.ExecutableTrace.OriginSummary)
	}
	if report.ExecutableTrace.SourceStageName != "build" || report.ExecutableTrace.SourceToolchain != "go" {
		t.Fatalf("unexpected source stage trace: %+v", report.ExecutableTrace)
	}
	if report.InheritsBuildStage || report.RunsInBuildEnv {
		t.Fatalf("expected separate static runtime, got InheritsBuildStage=%v RunsInBuildEnv=%v", report.InheritsBuildStage, report.RunsInBuildEnv)
	}
	if !report.UsesMultiStageCopy || report.MultiStagePattern != "multi-stage-copied-artifacts" {
		t.Fatalf("unexpected multi-stage pattern: %s", report.MultiStagePattern)
	}
	if !report.Hardening.MinimalBase || report.Hardening.BaseCategory != "minimal" {
		t.Fatalf("expected minimal base category, got %+v", report.Hardening)
	}
}

func TestDistinguishesInheritedBuildEnvironmentFromSeparateRuntime(t *testing.T) {
	inherited := `FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /app/server .

FROM build AS runtime
CMD ["/app/server"]
`
	repInherited, err := dockerfile.Analyze(inherited, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatalf("Analyze inherited failed: %v", err)
	}
	if !repInherited.InheritsBuildStage || !repInherited.RunsInBuildEnv {
		t.Fatalf("expected build-environment inheritance, got InheritsBuildStage=%v RunsInBuildEnv=%v", repInherited.InheritsBuildStage, repInherited.RunsInBuildEnv)
	}
	if repInherited.MultiStagePattern != "multi-stage-inherited-build" {
		t.Fatalf("MultiStagePattern = %q, want multi-stage-inherited-build", repInherited.MultiStagePattern)
	}
	if repInherited.RuntimeBase != "golang:1.22" {
		t.Fatalf("RuntimeBase = %q, want golang:1.22", repInherited.RuntimeBase)
	}
	wantChain := []string{"runtime", "build", "golang:1.22"}
	if !slices.Equal(repInherited.FromChain, wantChain) {
		t.Fatalf("FromChain = %v, want %v", repInherited.FromChain, wantChain)
	}

	separate := `FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /app/server .

FROM gcr.io/distroless/static-debian13:nonroot AS runtime
COPY --from=build /app/server /app/server
CMD ["/app/server"]
`
	repSeparate, err := dockerfile.Analyze(separate, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatalf("Analyze separate failed: %v", err)
	}
	if repSeparate.InheritsBuildStage || repSeparate.RunsInBuildEnv {
		t.Fatalf("expected separate runtime environment, got InheritsBuildStage=%v RunsInBuildEnv=%v", repSeparate.InheritsBuildStage, repSeparate.RunsInBuildEnv)
	}
	if !repSeparate.UsesMultiStageCopy || repSeparate.MultiStagePattern != "multi-stage-copied-artifacts" {
		t.Fatalf("MultiStagePattern = %q, want multi-stage-copied-artifacts", repSeparate.MultiStagePattern)
	}
	if repSeparate.RuntimeBase != "gcr.io/distroless/static-debian13:nonroot" {
		t.Fatalf("RuntimeBase = %q", repSeparate.RuntimeBase)
	}
}

func TestTargetSelectionAndBuildArgResolutionInFromChain(t *testing.T) {
	recipe := `ARG GO_VERSION=1.23
ARG FINAL_BASE=scratch
FROM golang:${GO_VERSION}-bookworm AS Base-Build
WORKDIR /workspace
RUN go build -o /bin/service ./cmd/service

FROM base-build AS dev-target
CMD ["/bin/service", "--dev"]

FROM ${FINAL_BASE} AS prod-target
COPY --from=base-build /bin/service /service
ENTRYPOINT ["/service"]
`
	// 1. Default target (last stage: prod-target) with custom build arg
	prod, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{
		BuildArgs: map[string]string{"FINAL_BASE": "zendis/static:1.0.0-rc.8-minimal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prod.TargetStageName != "prod-target" || prod.RuntimeBase != "zendis/static:1.0.0-rc.8-minimal" {
		t.Fatalf("unexpected prod trace: stage=%q base=%q", prod.TargetStageName, prod.RuntimeBase)
	}
	if prod.InheritsBuildStage || prod.RunsInBuildEnv {
		t.Fatalf("prod-target should not inherit build env")
	}

	// 2. Explicit --target dev-target (case-insensitive FROM base-build)
	dev, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{
		Target:    "DEV-TARGET",
		BuildArgs: map[string]string{"GO_VERSION": "1.24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dev.TargetStageName != "dev-target" || dev.RuntimeBase != "golang:1.24-bookworm" {
		t.Fatalf("unexpected dev trace: stage=%q base=%q", dev.TargetStageName, dev.RuntimeBase)
	}
	if !dev.InheritsBuildStage || !dev.RunsInBuildEnv {
		t.Fatalf("dev-target should inherit build stage")
	}

	// 3. Unknown target returns error
	if _, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{Target: "nonexistent"}); err == nil {
		t.Fatal("expected error for nonexistent target stage")
	}
}

func TestEntrypointAndCmdInheritanceSemantics(t *testing.T) {
	// In Docker, a child stage inherits ENTRYPOINT and CMD from its parent stage,
	// but redefining ENTRYPOINT in the child stage resets the inherited CMD!
	recipe := `FROM alpine:3.20 AS base
ENTRYPOINT ["/usr/bin/app"]
CMD ["--default-flag"]

FROM base AS keeps-both
USER 1000:1000

FROM base AS overrides-entrypoint
ENTRYPOINT ["/usr/bin/custom-app"]
`
	r1, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{Target: "keeps-both"})
	if err != nil {
		t.Fatal(err)
	}
	wantCmd1 := []string{"/usr/bin/app", "--default-flag"}
	if !slices.Equal(r1.EffectiveCommand, wantCmd1) {
		t.Fatalf("keeps-both EffectiveCommand = %v, want %v", r1.EffectiveCommand, wantCmd1)
	}
	if !r1.Entrypoint.InheritedFromStage || !r1.Cmd.InheritedFromStage {
		t.Fatalf("expected both ENTRYPOINT and CMD to be marked InheritedFromStage")
	}

	r2, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{Target: "overrides-entrypoint"})
	if err != nil {
		t.Fatal(err)
	}
	wantCmd2 := []string{"/usr/bin/custom-app"}
	if !slices.Equal(r2.EffectiveCommand, wantCmd2) || r2.Cmd != nil {
		t.Fatalf("overrides-entrypoint should reset inherited CMD; got EffectiveCommand=%v Cmd=%+v", r2.EffectiveCommand, r2.Cmd)
	}
}

func TestTransitiveCopyFromAndParserDirectives(t *testing.T) {
	recipe := strings.Join([]string{
		"# escape=`",
		"FROM rust:1.82 AS compile",
		"WORKDIR /src",
		"RUN <<EOF",
		"cargo build --release",
		"EOF",
		"",
		"FROM alpine:3.20 AS package",
		"COPY --from=compile /src/target/release/myapp `",
		"    # comment inside continuation line",
		"    /staging/myapp",
		"",
		"FROM scratch",
		"COPY --from=package /staging/myapp /myapp",
		"USER 65532:65532",
		`ENTRYPOINT ["/myapp"]`,
	}, "\n")
	rep, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if rep.RuntimeBase != "scratch" {
		t.Fatalf("RuntimeBase = %q, want scratch", rep.RuntimeBase)
	}
	if rep.ExecutableTrace.SourceStageName != "compile" || rep.ExecutableTrace.SourceToolchain != "rust" {
		t.Fatalf("expected transitive trace back to Rust compile stage, got %+v", rep.ExecutableTrace)
	}
	if rep.ExecutableTrace.OriginSummary != "Copied from the Rust build stage" {
		t.Fatalf("OriginSummary = %q", rep.ExecutableTrace.OriginSummary)
	}
	if rep.Hardening.Classification != "hardened" || rep.Hardening.UnhardenedScore != 0 {
		t.Fatalf("expected hardened score 0 for scratch + 65532:65532 + exec form, got %+v", rep.Hardening)
	}
}

func TestBreachBenchGeneratedRecipesScoreAsHardened(t *testing.T) {
	profiles := []struct {
		runtime string
		version string
		entry   string
	}{
		{"go", "1.27.2", "."},
		{"node", "24", "server.js"},
		{"next", "24", "server.js"},
	}

	for _, tc := range profiles {
		t.Run(tc.runtime, func(t *testing.T) {
			cfg := hardening.Config{
				Name:     "demo-" + tc.runtime,
				Runtime:  tc.runtime,
				Version:  tc.version,
				Platform: "linux/amd64",
				Entry:    tc.entry,
				Port:     8080,
				Build:    true,
			}
			recipe, err := hardening.ImageRecipe(t.TempDir(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := dockerfile.Analyze(recipe, dockerfile.TraceOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.InheritsBuildStage || rep.RunsInBuildEnv || !rep.UsesMultiStageCopy {
				t.Fatalf("%s recipe should use multi-stage artifact copy without build-env inheritance: %+v", tc.runtime, rep)
			}
			if rep.Hardening.RunsAsRoot || !rep.Hardening.NumericNonRootUser || !rep.Hardening.MinimalBase {
				t.Fatalf("%s recipe failed hardening checks: %+v", tc.runtime, rep.Hardening)
			}
			if rep.Hardening.Classification != "hardened" || rep.Hardening.UnhardenedScore != 0 {
				t.Fatalf("%s recipe expected hardened score 0, got %d (%s): %+v",
					tc.runtime, rep.Hardening.UnhardenedScore, rep.Hardening.Classification, rep.Hardening.Findings)
			}
		})
	}
}

func TestTerribleSingleStageDockerfileDetection(t *testing.T) {
	terrible := `FROM ubuntu:latest
WORKDIR /app
ENV API_SECRET="super-secret-value"
ADD . /app
RUN apt-get update && apt-get install -y python3 python3-pip curl sudo && \
    curl -fsSL https://example.com/install.sh | bash && \
    pip3 install -r requirements.txt && \
    chmod -R 777 /app
EXPOSE 80
CMD python3 app.py
`
	rep, err := dockerfile.Analyze(terrible, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SingleStage || !rep.RunsInBuildEnv || rep.UsesMultiStageCopy {
		t.Fatalf("expected single-stage build-env report, got SingleStage=%v RunsInBuildEnv=%v", rep.SingleStage, rep.RunsInBuildEnv)
	}
	if rep.Hardening.Classification != "terrible" || rep.Hardening.UnhardenedScore < 75 {
		t.Fatalf("expected terrible classification with high score, got %d (%s)", rep.Hardening.UnhardenedScore, rep.Hardening.Classification)
	}
	var codes []string
	for _, f := range rep.Hardening.Findings {
		codes = append(codes, f.Code)
	}
	for _, want := range []string{
		"single_stage_build",
		"full_os_runtime_base",
		"floating_latest_tag",
		"missing_user_instruction",
		"runtime_build_or_package_tools",
		"remote_script_pipe_to_shell",
		"permissive_chmod_or_setuid",
		"shell_form_startup",
		"add_instruction_used",
		"hardcoded_secret_env",
		"privileged_port_exposed",
	} {
		if !slices.Contains(codes, want) {
			t.Fatalf("missing finding %q in %v", want, codes)
		}
	}
}

func TestScrapePopularReposAndSaveArtifacts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"items": []map[string]any{
				{
					"full_name":        "org/terrible-app",
					"html_url":         "https://github.com/org/terrible-app",
					"description":      "Popular unhardened single-stage app",
					"stargazers_count": 42000,
					"language":         "Go",
					"default_branch":   "main",
				},
				{
					"full_name":        "org/inherited-build-app",
					"html_url":         "https://github.com/org/inherited-build-app",
					"description":      "Multi-stage app that still inherits FROM build",
					"stargazers_count": 31000,
					"language":         "TypeScript",
					"default_branch":   "main",
				},
				{
					"full_name":        "org/hardened-app",
					"html_url":         "https://github.com/org/hardened-app",
					"description":      "Properly hardened multi-stage static app",
					"stargazers_count": 25000,
					"language":         "Go",
					"default_branch":   "main",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/raw/org/terrible-app/main/Dockerfile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`FROM golang:latest
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y curl && go build -o server .
CMD ./server
`))
	})
	mux.HandleFunc("/raw/org/inherited-build-app/main/Dockerfile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`FROM node:22 AS build
WORKDIR /app
COPY . .
RUN npm install && npm run build

FROM build AS runtime
CMD ["npm", "start"]
`))
	})
	mux.HandleFunc("/raw/org/hardened-app/main/Dockerfile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app .

FROM zendis/static:1.0.0-rc.8-minimal@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
USER 65532:65532
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := dockerfile.ScrapePopularRepos(context.Background(), dockerfile.ScrapeOptions{
		Queries:            []string{"stars:>10000"},
		MaxReposWithDocker: 10,
		OnlyUnhardened:     true,
		NoMultiStageOnly:   true,
		APIBaseURL:         srv.URL,
		RawBaseURL:         srv.URL + "/raw",
		HTTPClient:         srv.Client(),
	}, nil)
	if err != nil {
		t.Fatalf("ScrapePopularRepos failed: %v", err)
	}

	if res.Summary.ReposWithDockerfile != 3 {
		t.Fatalf("ReposWithDockerfile = %d, want 3", res.Summary.ReposWithDockerfile)
	}
	if res.Summary.SingleStageCount != 1 || res.Summary.InheritedBuildStageCount != 1 || res.Summary.MultiStageCopyCount != 1 {
		t.Fatalf("unexpected stage counts: %+v", res.Summary)
	}
	if len(res.Unhardened) != 2 {
		t.Fatalf("expected 2 unhardened non-multistage repos, got %d", len(res.Unhardened))
	}
	if res.Unhardened[0].FullName != "org/terrible-app" || res.Unhardened[1].FullName != "org/inherited-build-app" {
		t.Fatalf("unexpected unhardened ranking: %s, %s", res.Unhardened[0].FullName, res.Unhardened[1].FullName)
	}

	outDir := filepath.Join(t.TempDir(), "scrape-out")
	if err := dockerfile.SaveScrapeArtifacts(outDir, res); err != nil {
		t.Fatalf("SaveScrapeArtifacts failed: %v", err)
	}
	for _, f := range []string{"results.json", "report.md", "report.html", "dockerfiles/org__terrible-app__Dockerfile.Dockerfile"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Fatalf("expected artifact %s: %v", f, err)
		}
	}
	mdBytes, err := os.ReadFile(filepath.Join(outDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdBytes), "org/terrible-app") || !strings.Contains(string(mdBytes), "multi-stage-inherited-build") {
		t.Fatalf("report.md missing expected details")
	}
}

func TestUnresolvedBuildArgInFromAndMetadataBaseStage(t *testing.T) {
	unresolved := `ARG BUILD_FROM
FROM ${BUILD_FROM}
COPY rootfs /
`
	rep, err := dockerfile.Analyze(unresolved, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.RuntimeBase != "${BUILD_FROM}" {
		t.Fatalf("RuntimeBase = %q, want ${BUILD_FROM}", rep.RuntimeBase)
	}
	if rep.Hardening.BaseCategory != "unresolved-build-arg" {
		t.Fatalf("BaseCategory = %q, want unresolved-build-arg", rep.Hardening.BaseCategory)
	}
	if !slices.Contains(rep.UnresolvedArgs, "BUILD_FROM") {
		t.Fatalf("expected BUILD_FROM in UnresolvedArgs, got %v", rep.UnresolvedArgs)
	}

	// Metadata-only intermediate base stage should not be misclassified as inheriting a build stage
	metadataAlias := `FROM golang:1.23 AS build
WORKDIR /src
RUN go build -o /out/server .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef AS base-runtime
LABEL org.opencontainers.image.vendor="example"

FROM base-runtime
USER 65532:65532
COPY --from=build /out/server /server
ENTRYPOINT ["/server"]
`
	rep2, err := dockerfile.Analyze(metadataAlias, dockerfile.TraceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.InheritsBuildStage {
		t.Fatalf("metadata-only base-runtime should not set InheritsBuildStage=true")
	}
	if !rep2.UsesMultiStageCopy || rep2.MultiStagePattern != "multi-stage-copied-artifacts" {
		t.Fatalf("expected multi-stage-copied-artifacts, got %q (UsesMultiStageCopy=%v)", rep2.MultiStagePattern, rep2.UsesMultiStageCopy)
	}
}
