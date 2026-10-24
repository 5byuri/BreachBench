# 🛡️ BreachBench — Project Submission

## 1. What Are We Building? (Description)

**BreachBench** is an automated **OCI Container Hardening & Adversarial Security Benchmarking Platform** built on top of the OCI Community’s [Container Hardening Work Bench (`deb2scratch`)](https://gitlab.opencode.de/oci-community/tools/container-hardening-work-bench).

BreachBench bridges **defensive container hardening** and **offensive adversarial verification** in a single end-to-end pipeline:

1. **Automated GitHub Distro-Dockerfile Discovery & Scraper (`harden-pr`)**
   - Scans GitHub repositories (by star rank or regex/API search) to identify production `Dockerfile`s running on bloated, unhardened OS base images (`ubuntu`, `debian`, `python`, `node`, `golang`, etc.)—even resolving multi-stage `FROM ... AS ...` aliases and `ARG` variables.
2. **Deterministic `deb2scratch` Container Hardener**
   - Automatically transforms standard distro-based `Dockerfile`s into minimal, zero-OS `FROM scratch` multi-stage builds.
   - Extracts only the exact runtime shared libraries (`ldd` + `apt-rdepends`), strips out shells (`/bin/sh`, `/bin/bash`), package managers (`apt`, `dpkg`), and coreutils, generates an embedded Software Bill of Materials (`SBOM.txt`), and enforces unprivileged non-root execution (`USER 53111:53111`).
3. **Adversarial Sandbox Benchmarking (Red-Team Verification)**
   - Runs isolated, deterministic offensive security benchmarks against the unhardened image vs. the hardened `FROM scratch` image inside a locked-down sandbox—proving measurably whether an exploit/post-exploitation chain is **pwned or blocked** when shells, package managers, and root privileges are removed.
4. **Autonomous GitHub Pull Request Bot**
   - Forks target upstream repositories, commits the hardened `Dockerfile` alongside a before/after security audit report, and opens ready-to-merge Pull Requests automatically.

---

## 2. Which Bounty or Bounties Are You Building For?

We are building for the following hackathon tracks and bounties at the **Encode Hub Hackathon**:

- **Cybersecurity / AI & Autonomous Security Agents Track**: Combining deterministic static/build-time container hardening (`deb2scratch`) with sandboxed offensive AI benchmarking ("pwned vs. not pwned") and autonomous GitHub PR remediation.
- **Open-Source Infrastructure & DevSecOps Tooling Bounty**: Proactively securing the open-source ecosystem at scale—demonstrated by automatically discovering and hardening the **Top 10 most-starred GitHub repositories** shipping unhardened distro containers (including `ollama/ollama`, `freeCodeCamp/freeCodeCamp`, `openclaw/openclaw`, `microsoft/markitdown`, `langgenius/dify`, and `open-webui/open-webui`, representing **2.2M+ combined GitHub stars**).
- **Cloud-Native / OCI Container Security & Compliance Track**: Implementing zero-trust OCI container hardening, automated SBOM generation, Rego/Kubernetes IaC policy enforcement, and non-root execution out of the box.

---

## 3. What Problem Are You Solving, and For Who?

### The Problem

1. **90%+ of Open-Source & Production Containers Ship a Full Linux OS to Run a Single Binary or Script**
   - Developers write "quickstart" or distro-based `Dockerfile`s (`FROM ubuntu:24.04`, `FROM python:3.11-slim`, `FROM node:24-bookworm`) that bundle hundreds of megabytes of unnecessary OS utilities (`bash`, `curl`, `apt`, `tar`, `perl`, compilers) and run as `root` (`UID 0`) by default.
   - If an attacker achieves Remote Code Execution (RCE) in the application layer, those leftover OS utilities and root privileges hand them an immediate **living-off-the-land post-exploitation toolkit** to download payloads, pivot across the cluster, or escape the container.
2. **Existing Alternatives Like Google's `distroless` Are Hard to Adopt**
   - `distroless` only provides fixed base images for a few runtimes and makes installing custom C/C++ shared libraries (like `ffmpeg`, `libvulkan1`, `libopenblas0`, `poppler-utils`) painful because there is no package manager.
   - Manually crafting a `FROM scratch` image requires manually tracing every transitive `.so` dynamic library with `ldd` and `dpkg`, which most developers will never do by hand.
3. **Security Scanners Only Report CVEs—They Don't Fix Them or Prove Exploitability**
   - Traditional scanners flood teams with thousands of CVE alerts without fixing the `Dockerfile` or proving whether an attacker can actually exploit the container in practice.

### Who We Are Solving It For

- **Open-Source Maintainers & Application Developers**: Who want the convenience of `apt-get install` during build time, but need an automated drop-in tool (or GitHub PR bot) that compiles their image down to a zero-CVE, shell-less `FROM scratch` runtime without breaking dynamic libraries.
- **DevSecOps & Platform Engineering Teams**: Who need deterministic, reproducible, non-root (`USER 53111:53111`) container images with built-in SBOMs to meet enterprise and public-sector hardening standards (such as BSI / OCI Community Container Hardening guidelines).
- **Security Researchers & Red Teams**: Who need a repeatable benchmark (`BreachBench`) to test offensive AI agents and exploit chains against unhardened vs. hardened container sandboxes and quantify real-world attack-surface reduction.
