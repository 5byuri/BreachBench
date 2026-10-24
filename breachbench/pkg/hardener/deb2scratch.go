package hardener

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

const deb2ScratchContainerfileTemplate = `# =============================================================================
# Hardened by BreachBench + OCI Community Container Hardening Work Bench
# Original Base Image: {{.OriginalBaseImage}} -> Hardened Runtime: scratch (non-root 53111:53111)
# =============================================================================
FROM {{.BuilderBaseImage}} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    UCF_FORCE_CONFFNEW=1

# Create minimal distroless-style rootfs hierarchy
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/usr/share /rootfs/lib /rootfs/usr/lib \
             /rootfs/usr/bin /rootfs/bin /rootfs/tmp /rootfs/var /rootfs/home/nonroot && \
    chmod 1777 /rootfs/tmp

# Install required packages + dependency resolver for minimal rootfs extraction
RUN apt-get update && \
    apt-get install -y --no-install-recommends apt-rdepends ca-certificates {{.PackageListSpace}} && \
    dpkg-architecture -qDEB_HOST_MULTIARCH > /tmp/multiarch.txt && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Extract only required package binaries and ldd-verified shared libraries into /rootfs
RUN set -eux; \
    for pkg in {{.PackageListSpace}}; do \
        dpkg -L "$pkg" 2>/dev/null || true; \
    done | sort -u > /tmp/package-files.txt; \
    while IFS= read -r file; do \
        if [ -f "$file" ] && [ ! -d "$file" ]; then \
            case "$file" in \
                /usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*|/usr/lib/*.so*|/lib/*.so*|/etc/*.conf) \
                    mkdir -p "/rootfs$(dirname "$file")" && cp -a "$file" "/rootfs$file" || true ;; \
            esac; \
            if [ -x "$file" ]; then \
                ldd "$file" 2>/dev/null | awk '/=>/ {print $3}' | while read -r lib; do \
                    if [ -n "$lib" ] && [ -f "$lib" ]; then \
                        mkdir -p "/rootfs$(dirname "$lib")" && cp -Ln "$lib" "/rootfs$lib" || true; \
                    fi; \
                done; \
            fi; \
        fi; \
    done < /tmp/package-files.txt; \
    MULTIARCH=$(cat /tmp/multiarch.txt); \
    find /lib/$MULTIARCH /lib /lib64 -name 'ld-linux*.so.*' -o -name 'libc.so.*' 2>/dev/null | while read -r rt; do \
        mkdir -p "/rootfs$(dirname "$rt")" && cp -Ln "$rt" "/rootfs$rt" || true; \
    done; \
    cp -a /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ 2>/dev/null || true

# Configure unprivileged nonroot user (UID/GID 53111) and strip interactive login shell
RUN echo 'nonroot:x:53111:53111:nonroot:/home/nonroot:/sbin/nologin' > /rootfs/etc/passwd && \
    echo 'nonroot:x:53111:' > /rootfs/etc/group && \
    chown -R 53111:53111 /rootfs/home/nonroot

# Generate embedded CycloneDX 1.5 SBOM (/rootfs/sbom.json)
RUN cat > /usr/local/bin/generate_sbom <<'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail
root_packages=(
{{- range .AptPackages }}
    "{{ . }}"
{{- end }}
)
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":['
for i in "${!root_packages[@]}"; do
  pkg="${root_packages[$i]}"
  ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo 'unknown')
  sep=$([ $i -lt $((${#root_packages[@]}-1)) ] && echo ',' || echo '')
  echo "  {\"type\":\"library\",\"name\":\"$pkg\",\"version\":\"$ver\"}$sep"
done
echo ']}'
SCRIPT_EOF
RUN chmod +x /usr/local/bin/generate_sbom && /usr/local/bin/generate_sbom > /rootfs/sbom.json
{{- if or .FinalCopySteps .AppBuildSteps }}

# Preserve application build and asset steps inside builder stage
{{- range .FinalCopySteps }}
{{ . }}
{{- end }}
{{- range .AppBuildSteps }}
{{ . }}
{{- end }}
{{- end }}

# =============================================================================
# Final Hardened Runtime Stage (Zero-OS Scratch Image)
# =============================================================================
FROM scratch

COPY --from=builder --chown=53111:53111 /rootfs/ /
{{- range .EnvVars }}
ENV {{ . }}
{{- end }}
{{- if .Workdir }}
WORKDIR {{ .Workdir }}
{{- end }}
{{- range .ExposePorts }}
EXPOSE {{ . }}
{{- end }}

# Enforce non-root execution (OCI Container Hardening Checklist)
USER 53111:53111
{{- if .Entrypoint }}
ENTRYPOINT {{ .Entrypoint }}
{{- end }}
{{- if .Cmd }}
CMD {{ .Cmd }}
{{- end }}
`

type templateRenderData struct {
	*DockerfileAnalysis
	PackageListSpace string
}

// RenderHardenedDockerfile renders a hardened multi-stage FROM scratch Containerfile
// following the OCI Community Container Hardening Work Bench (deb2scratch) pattern.
func RenderHardenedDockerfile(analysis *DockerfileAnalysis) (string, error) {
	if analysis == nil {
		return "", fmt.Errorf("dockerfile analysis cannot be nil")
	}

	pkgs := analysis.AptPackages
	if len(pkgs) == 0 {
		pkgs = []string{"ca-certificates", "tzdata"}
	}

	tmpl, err := template.New("deb2scratch").Parse(deb2ScratchContainerfileTemplate)
	if err != nil {
		return "", fmt.Errorf("parse deb2scratch template: %w", err)
	}

	data := templateRenderData{
		DockerfileAnalysis: analysis,
		PackageListSpace:   strings.Join(pkgs, " "),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute deb2scratch template: %w", err)
	}

	return buf.String(), nil
}
