package imagehardening

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// This is a bounded removal tool, not a package uninstaller or application editor.
var removableTools = []string{
	"/bin/sh", "/bin/bash", "/bin/ash", "/bin/dash", "/bin/zsh", "/bin/busybox", "/busybox",
	"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/ash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/busybox",
	"/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/curl", "/usr/bin/wget",
	"/usr/local/bin/npm", "/usr/local/bin/npx", "/usr/local/bin/corepack", "/usr/local/bin/yarn", "/usr/local/bin/yarnpkg",
	"/usr/bin/npm", "/usr/bin/npx", "/usr/bin/corepack", "/usr/bin/yarn", "/usr/bin/yarnpkg",
}

type localImageMetadata struct {
	ID, Architecture, OS, Variant string
	Config                        map[string]json.RawMessage
}

type imageRebuildEvidence struct {
	RemovedEntries           []string `json:"removed_entries"`
	RetainedEntries          int      `json:"retained_entries"`
	RetainedBytes            int64    `json:"retained_bytes"`
	RootfsSHA256             string   `json:"rootfs_sha256"`
	ApplicationFilesModified bool     `json:"application_files_modified"`
	Method                   string   `json:"method"`
}

func inspectLocalMetadata(ctx context.Context, image string) (localImageMetadata, error) {
	var metadata []localImageMetadata
	data, err := capture(ctx, "docker", "image", "inspect", "--", image)
	if err != nil || len(data) > 2*1024*1024 || json.Unmarshal(data, &metadata) != nil || len(metadata) != 1 || !slimImageID(metadata[0].ID) || metadata[0].Config == nil {
		return localImageMetadata{}, errors.New("cannot inspect local image configuration")
	}
	if metadata[0].OS != "linux" {
		return localImageMetadata{}, errors.New("this hardener supports Linux container images, not Windows container images")
	}
	return metadata[0], nil
}

func shellRequired(metadata localImageMetadata) bool {
	for _, key := range []string{"Entrypoint", "Cmd"} {
		var argv []string
		_ = json.Unmarshal(metadata.Config[key], &argv)
		if len(argv) == 0 {
			continue
		}
		name := path.Base(argv[0])
		if name == "sh" || name == "bash" || name == "ash" || name == "dash" || name == "zsh" || name == "busybox" || strings.HasSuffix(name, ".sh") {
			return true
		}
	}
	var health struct{ Test []string }
	_ = json.Unmarshal(metadata.Config["Healthcheck"], &health)
	return len(health.Test) > 0 && health.Test[0] == "CMD-SHELL"
}

func defaultToolRemovals(metadata localImageMetadata) []string {
	var health struct{ Test []string }
	_ = json.Unmarshal(metadata.Config["Healthcheck"], &health)
	if len(health.Test) > 0 && health.Test[0] != "NONE" {
		return []string{}
	}
	var required []string
	for _, key := range []string{"Entrypoint", "Cmd"} {
		var argv []string
		_ = json.Unmarshal(metadata.Config[key], &argv)
		if len(argv) > 0 {
			required = append(required, path.Base(argv[0]))
		}
	}
	result := []string{}
	for _, item := range removableTools {
		if shellRequired(metadata) && isShellTool(item) {
			continue
		}
		needed := false
		for _, executable := range required {
			needed = needed || path.Base(item) == executable
		}
		if !needed {
			result = append(result, item)
		}
	}
	return result
}

func isShellTool(value string) bool {
	name := path.Base(value)
	return name == "sh" || name == "bash" || name == "ash" || name == "dash" || name == "zsh" || name == "busybox"
}

func validateToolRemovals(removals []string) error {
	if len(removals) > len(removableTools) {
		return errors.New("too many removal paths")
	}
	for _, item := range removals {
		allowed := false
		for _, candidate := range removableTools {
			allowed = allowed || item == candidate
		}
		if !allowed {
			return errors.New("only the fixed shell/package/download tool entrypoints may be removed; app and runtime files cannot be selected")
		}
	}
	return nil
}

// Repack a Docker-exported rootfs as one layer. No untrusted archive is extracted
// on the host, and no command or package manager is required inside the image.
func rebuildImage(ctx context.Context, source, target, user, artifactDir string, removals []string) (evidence imageRebuildEvidence, resultErr error) {
	if err := validateToolRemovals(removals); err != nil {
		return evidence, err
	}
	if err := genericUser(user); err != nil {
		return evidence, err
	}
	if err := newImageTag(ctx, target); err != nil {
		return evidence, err
	}
	metadata, err := inspectLocalMetadata(ctx, source)
	if err != nil {
		return evidence, err
	}
	dir, err := os.MkdirTemp(artifactDir, "repack-")
	if err != nil {
		return evidence, err
	}
	defer os.RemoveAll(dir)
	name := fmt.Sprintf("hardening-export-%d-%d", os.Getpid(), time.Now().UnixNano())
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-fv", name).Run()
	}()
	if _, err := capture(ctx, "docker", "create", "--name", name, "--label=container-hardening-work-bench.export=true", "--network=none", "--entrypoint=/.not-executed", metadata.ID); err != nil {
		return evidence, err
	}
	exported := filepath.Join(dir, "export.tar")
	if _, err := capture(ctx, "docker", "container", "export", "--output", exported, name); err != nil {
		return evidence, err
	}
	input, err := os.Open(exported)
	if err != nil {
		return evidence, err
	}
	layer, err := os.OpenFile(filepath.Join(dir, "layer.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		_ = input.Close()
		return evidence, err
	}
	hash := sha256.New()
	evidence, err = filterRootfs(ctx, input, io.MultiWriter(layer, hash), removals)
	closeInputErr := input.Close()
	if err := errors.Join(err, closeInputErr); err != nil {
		_ = layer.Close()
		return evidence, err
	}
	evidence.RootfsSHA256 = hex.EncodeToString(hash.Sum(nil))
	if _, err := layer.Seek(0, io.SeekStart); err != nil {
		_ = layer.Close()
		return evidence, err
	}
	config, err := rebuiltConfig(metadata, user, evidence.RootfsSHA256)
	if err != nil {
		_ = layer.Close()
		return evidence, err
	}
	archive, err := os.OpenFile(filepath.Join(dir, "image.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		_ = layer.Close()
		return evidence, err
	}
	info, err := layer.Stat()
	if err != nil {
		_ = layer.Close()
		_ = archive.Close()
		return evidence, err
	}
	err = writeImageArchive(archive, config, layer, info.Size(), target)
	if err := errors.Join(err, layer.Close(), archive.Close()); err != nil {
		return evidence, err
	}
	if _, err := capture(ctx, "docker", "image", "load", "--input", filepath.Join(dir, "image.tar")); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func filterRootfs(ctx context.Context, input io.Reader, output io.Writer, removals []string) (evidence imageRebuildEvidence, resultErr error) {
	evidence.RemovedEntries = []string{}
	evidence.Method = "Docker export, streaming TAR entry filtering, original runtime config preserved, Docker image load; no application code or component upgrades"
	if err := validateToolRemovals(removals); err != nil {
		return evidence, err
	}
	remove := map[string]bool{}
	for _, item := range removals {
		remove[strings.TrimPrefix(item, "/")] = true
	}
	reader, writer := tar.NewReader(input), tar.NewWriter(output)
	defer func() { resultErr = errors.Join(resultErr, writer.Close()) }()
	for {
		if err := ctx.Err(); err != nil {
			return evidence, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return evidence, err
		}
		name := strings.TrimPrefix(header.Name, "./")
		clean := path.Clean(name)
		if path.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, "../") {
			return evidence, errors.New("unsafe exported archive path")
		}
		if remove[clean] {
			if header.Typeflag == tar.TypeDir {
				return evidence, errors.New("refusing recursive directory removal at a tool entrypoint")
			}
			evidence.RemovedEntries = append(evidence.RemovedEntries, "/"+clean)
			continue
		}
		if header.Typeflag == tar.TypeLink {
			link := path.Clean(strings.TrimPrefix(header.Linkname, "./"))
			if link == ".." || strings.HasPrefix(link, "../") {
				return evidence, errors.New("unsafe exported hardlink target")
			}
			link = strings.TrimPrefix(link, "/")
			if remove[link] {
				return evidence, errors.New("a retained hardlink depends on a removed tool; retain that tool")
			}
		}
		if err := writer.WriteHeader(header); err != nil {
			return evidence, err
		}
		copied, err := io.Copy(writer, reader)
		if err != nil {
			return evidence, err
		}
		evidence.RetainedEntries++
		evidence.RetainedBytes += copied
	}
	return evidence, nil
}

func rebuiltConfig(metadata localImageMetadata, user, rootfsSHA string) ([]byte, error) {
	config := map[string]json.RawMessage{}
	for key, value := range metadata.Config {
		config[key] = value
	}
	config["User"], _ = json.Marshal(user)
	return json.Marshal(map[string]any{
		"architecture": metadata.Architecture, "os": metadata.OS, "variant": metadata.Variant,
		"config": config, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + rootfsSHA}},
		"history": []map[string]string{{"created_by": "container-hardening-work-bench: retained original filesystem bytes; removed selected tool entries"}},
	})
}

func writeImageArchive(output io.Writer, config []byte, layer io.Reader, layerSize int64, tag string) (resultErr error) {
	writer := tar.NewWriter(output)
	defer func() { resultErr = errors.Join(resultErr, writer.Close()) }()
	digest := sha256.Sum256(config)
	configName := hex.EncodeToString(digest[:]) + ".json"
	manifest, err := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{tag}, "Layers": []string{"layer.tar"}}})
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{configName, config}, {"manifest.json", manifest}} {
		if err := writer.WriteHeader(&tar.Header{Name: item.name, Mode: 0600, Size: int64(len(item.data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := writer.Write(item.data); err != nil {
			return err
		}
	}
	if err := writer.WriteHeader(&tar.Header{Name: "layer.tar", Mode: 0600, Size: layerSize, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.CopyN(writer, layer, layerSize)
	return err
}
