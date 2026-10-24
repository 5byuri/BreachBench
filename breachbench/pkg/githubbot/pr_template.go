package githubbot

import (
	"fmt"
	"strings"
)

// PRReportData holds the metadata used to render a rich hardening Pull Request description.
type PRReportData struct {
	RepoFullName      string
	DockerfilePath    string
	OriginalBaseImage string
	BuilderBaseImage  string
	AptPackages       []string
	DetectedIssues    []string
	EntrypointOrCmd   string
}

// RenderPRBody generates a presentation-ready Markdown Pull Request body detailing the
// container security posture transformation performed by BreachBench + deb2scratch.
func RenderPRBody(data PRReportData) string {
	repoName := data.RepoFullName
	if repoName == "" {
		repoName = "target-repository"
	}
	dockerfilePath := data.DockerfilePath
	if dockerfilePath == "" {
		dockerfilePath = "Dockerfile"
	}
	origBase := data.OriginalBaseImage
	if origBase == "" {
		origBase = "debian/ubuntu (full OS rootfs)"
	}
	builderBase := data.BuilderBaseImage
	if builderBase == "" {
		builderBase = origBase
	}
	entrypoint := data.EntrypointOrCmd
	if entrypoint == "" {
		entrypoint = "(preserved from original Dockerfile)"
	}

	var b strings.Builder

	b.WriteString("## 🛡️ BreachBench Automated Container Hardening (`deb2scratch`)\n\n")
	b.WriteString(fmt.Sprintf(
		"> **Automated Zero-Distro Migration** for [`%s`](https://github.com/%s) (`%s`) powered by **BreachBench** & the **OCI Community Container Hardening Work Bench (`deb2scratch`)**.\n\n",
		repoName, repoName, dockerfilePath,
	))
	b.WriteString("This Pull Request refactors the container build pipeline into a hardened multi-stage build that compiles and extracts strictly required ELF binaries and their recursive shared-library closure (`ldd`) into an immutable `FROM scratch` runtime image.\n\n")

	b.WriteString("### 📊 Security Posture Scorecard (Before vs. After)\n\n")
	b.WriteString("| Security Dimension | ❌ Before (Original Image) | ✅ After (`deb2scratch` Hardened) | Security Impact |\n")
	b.WriteString("| :--- | :--- | :--- | :--- |\n")
	b.WriteString(fmt.Sprintf("| **Runtime Base Image** | `%s` | `scratch` (Distroless Minimal Rootfs) | Eliminates 95%%+ of OS-layer CVEs |\n", origBase))
	b.WriteString("| **Runtime User Privilege** | `root (UID 0)` | `nonroot (53111:53111)` | Prevents privileged container breakout |\n")
	b.WriteString("| **Interactive Shells** | `/bin/bash`, `/bin/sh` present | **Stripped** (`/sbin/nologin`) | Blocks RCE-to-interactive-shell spawning |\n")
	b.WriteString("| **Package Managers** | `apt`, `dpkg` present | **Stripped** | Prevents post-exploitation tool install |\n")
	b.WriteString("| **Shared Libraries** | Full distro `/usr/lib` | **`ldd`-traced & SHA-256 deduplicated** | Only exact `.so` libraries required by binaries |\n")
	b.WriteString("| **Supply Chain SBOM** | None | **Embedded CycloneDX 1.5 (`/sbom.json`)** | Instant CVE & provenance auditing |\n\n")

	b.WriteString("### 🔍 Detected Vulnerabilities & Risks Remediated\n\n")
	if len(data.DetectedIssues) > 0 {
		for _, issue := range data.DetectedIssues {
			b.WriteString(fmt.Sprintf("- ❌ %s\n", issue))
		}
	} else {
		b.WriteString("- ❌ Full OS userland, interactive shells (`/bin/sh`, `/bin/bash`), and package managers (`apt`, `dpkg`) exposed at runtime.\n")
		b.WriteString("- ❌ Privileged default `root (UID 0)` container execution context.\n")
	}
	b.WriteString("\n")

	b.WriteString("### 🏗️ Hardening Pipeline Architecture\n\n")
	b.WriteString("```mermaid\n")
	b.WriteString("flowchart LR\n")
	b.WriteString(fmt.Sprintf("    A[\"Original %s\\n(%s)\"] --> B[\"Stage 1: Builder (%s)\\napt-get + ldd Binary/Lib Extraction\\n+ CycloneDX SBOM Generation\"]\n", dockerfilePath, origBase, builderBase))
	b.WriteString("    B --> C[\"Stage 2: FROM scratch\\nCOPY /rootfs (chown 53111:53111)\\nUSER 53111:53111 (No Shell / No Apt)\"]\n")
	b.WriteString("```\n\n")

	b.WriteString("### 📦 Extracted Runtime Dependencies & Entrypoint\n\n")
	if len(data.AptPackages) > 0 {
		var quoted []string
		for _, pkg := range data.AptPackages {
			quoted = append(quoted, fmt.Sprintf("`%s`", pkg))
		}
		b.WriteString(fmt.Sprintf("- **Traced Debian/Ubuntu Packages:** %s\n", strings.Join(quoted, ", ")))
	} else {
		b.WriteString("- **Traced Debian/Ubuntu Packages:** Base runtime libraries (`libc`, `libssl`, `ca-certificates`) + application binary closure\n")
	}
	b.WriteString(fmt.Sprintf("- **Preserved Runtime Entrypoint / Command:** `%s`\n", entrypoint))
	b.WriteString("- **Non-Root Execution UID/GID:** `53111:53111` (`/etc/passwd` & `/etc/group` synthesized in `/rootfs`)\n")
	b.WriteString("- **Embedded SBOM Path:** `/sbom.json` (CycloneDX 1.5 JSON format)\n\n")

	b.WriteString("---\n")
	b.WriteString("*Generated autonomously by **BreachBench Hardening Bot** (`breachbench harden-pr`) using the [OCI Community Container Hardening Work Bench (`deb2scratch`)](https://gitlab.opencode.de/oci-community/tools/container-hardening-work-bench).*\n")

	return b.String()
}
