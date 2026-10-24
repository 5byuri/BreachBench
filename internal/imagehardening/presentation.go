package imagehardening

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/charmbracelet/x/term"
)

func genericOutputFormat(value string, out io.Writer) (string, error) {
	switch value {
	case "json", "human":
		return value, nil
	case "auto":
		if file, ok := out.(interface{ Fd() uintptr }); ok && term.IsTerminal(file.Fd()) {
			return "human", nil
		}
		return "json", nil
	default:
		return "", errors.New("--format must be auto, human, or json")
	}
}

func (config genericConfig) phase(message string, passed bool) {
	if config.Progress != nil {
		config.Progress(message, passed)
	}
}

// Plain text intentionally needs no color/NO_COLOR handling and never emits ANSI.
func terminalText(value string, limit int) string {
	var text strings.Builder
	count := 0
	for _, char := range value {
		if count == limit {
			text.WriteString("...")
			break
		}
		if unicode.IsControl(char) || unicode.In(char, unicode.Cf) {
			char = ' '
		}
		text.WriteRune(char)
		count++
	}
	return strings.TrimSpace(text.String())
}

func writeGenericHumanHeader(out io.Writer, config genericConfig) error {
	mode := config.Mode + " (no model)"
	if config.Mode == "argon" {
		mode = "argon / " + config.Model
	}
	_, err := fmt.Fprintf(out, "BreachBench | image hardening\n\nMode:   %s\nSource: %s\nTarget: %s\n\n", terminalText(mode, 120), terminalText(config.Image, 160), terminalText(config.Target, 160))
	return err
}

type humanRow struct{ check, before, after, status string }

func writeGenericHuman(out io.Writer, config genericConfig, report *genericReport, runErr error) error {
	if report == nil {
		report = &genericReport{}
	}
	rows := genericHumanRows(report)
	status := "PASS"
	if !report.Completed {
		status = "INCOMPLETE"
	}
	for _, row := range rows {
		if row.status == "INCOMPLETE" && status != "FAILED" {
			status = "INCOMPLETE"
		}
		if row.status == "FAILED" {
			status = "FAILED"
		}
	}
	if runErr != nil || report.Error != "" {
		status = "FAILED"
	}
	var text strings.Builder
	fmt.Fprintf(&text, "\nResult: %s\n\n", status)
	table := tabwriter.NewWriter(&text, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CHECK\tBEFORE\tAFTER\tRESULT")
	for _, row := range rows {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", terminalText(row.check, 36), terminalText(row.before, 38), terminalText(row.after, 38), row.status)
	}
	_ = table.Flush()
	if len(report.Attempts) > 0 {
		last := report.Attempts[len(report.Attempts)-1]
		if last.Rebuild != nil && toolDigest(last.Rebuild.RootfsSHA256) {
			fmt.Fprintf(&text, "\nActual tool entries removed in final candidate: %d\n", len(last.Rebuild.RemovedEntries))
		}
	}
	if runErr != nil {
		fmt.Fprintf(&text, "\nReason: %s\n", terminalText(runErr.Error(), 240))
	} else if report.Error != "" {
		fmt.Fprintf(&text, "\nReason: %s\n", terminalText(report.Error, 240))
	}
	if status == "PASS" {
		fmt.Fprintf(&text, "\nValidated image: %s\n", terminalText(report.Image, 160))
	}
	directory, err := filepath.Abs(config.Artifacts)
	if config.Artifacts != "" && err == nil {
		label := "Artifacts"
		if !report.Completed || runErr != nil {
			label = "Evidence paths (files may be partial)"
		}
		fmt.Fprintf(&text, "\n%s:\n", label)
		for _, name := range []string{"report.json", "comparison.md", "compose.json"} {
			fmt.Fprintf(&text, "  %s\n", terminalText(filepath.Join(directory, name), 220))
		}
	}
	fmt.Fprintln(&text, "\nScope: declared application checks and listed shell commands only. Required tools may remain.")
	fmt.Fprintln(&text, "Runtime restrictions require compose.json in deployment. Egress was NOT TESTED.")
	fmt.Fprintln(&text, "Hardening does not patch vulnerabilities or prevent all runtime code execution.")
	_, err = io.WriteString(out, text.String())
	return err
}

func genericHumanRows(report *genericReport) []humanRow {
	beforeApp, beforeStatus := humanWorkload(report.BaselineWorkload)
	candidateWorkload := report.CandidateWorkload
	if candidateWorkload == nil && len(report.Attempts) > 0 {
		candidateWorkload = report.Attempts[len(report.Attempts)-1].Workload
	}
	afterApp, afterStatus := humanWorkload(candidateWorkload)
	rows := []humanRow{{"Application checks", beforeApp, afterApp, humanCombined(beforeStatus, afterStatus)}}
	a, b := report.BaselineProbe, report.CandidateProbe
	identity := "INCOMPLETE"
	if validHumanProbe(a) && validHumanProbe(b) {
		identity = "PASS"
		parts := strings.Split(report.Policy.User, ":")
		if len(parts) != 2 {
			identity = "INCOMPLETE"
		} else {
			uid, uidErr := strconv.ParseUint(parts[0], 10, 32)
			gid, gidErr := strconv.ParseUint(parts[1], 10, 32)
			if uidErr != nil || gidErr != nil {
				identity = "INCOMPLETE"
			} else if b.UID == 0 || uint64(b.UID) != uid || uint64(b.GID) != gid {
				identity = "FAILED"
			}
		}
	}
	rows = append(rows, humanRow{"Effective UID:GID", humanIdentity(a), humanIdentity(b), identity})
	beforeWrites, beforeState := humanWrites(a, false)
	afterWrites, afterState := humanWrites(b, true)
	rows = append(rows, humanRow{"Protected root writes", beforeWrites, afterWrites, humanCombined(beforeState, afterState)})
	beforeShells, beforeState := humanShells(a)
	afterShells, afterState := humanShells(b)
	shellState := humanCombined(beforeState, afterState)
	if shellState == "PASS" {
		shellState = "OBSERVED"
	}
	rows = append(rows, humanRow{"Tested shells (accessible)", beforeShells, afterShells, shellState})
	beforeInstall, beforeState := humanInstall(a, false)
	afterInstall, afterState := humanInstall(b, true)
	rows = append(rows, humanRow{"Install into protected root", beforeInstall, afterInstall, humanCombined(beforeState, afterState)})
	retained, retainedState := "Not confirmed", "INCOMPLETE"
	if len(report.Attempts) > 0 {
		if rebuild := report.Attempts[len(report.Attempts)-1].Rebuild; rebuild != nil {
			if rebuild.ApplicationFilesModified {
				retained, retainedState = "Reported modified", "FAILED"
			} else if toolDigest(rebuild.RootfsSHA256) && rebuild.RetainedEntries > 0 {
				retained, retainedState = "Copied unchanged", "PASS"
			}
		}
	}
	rows = append(rows, humanRow{"Retained app/runtime bytes", "Original", retained, retainedState})
	network := report.Policy.Network
	networkState := "CONFIGURED"
	if network != "none" && network != "internal" && network != "bridge" {
		network = "Not configured"
		networkState = "INCOMPLETE"
	}
	if network == "bridge" {
		network = "bridge (external egress allowed)"
	}
	rows = append(rows, humanRow{"Test network (configured)", network, network, networkState}, humanRow{"Egress connectivity", "NOT TESTED", "NOT TESTED", "NOT TESTED"})
	return rows
}

func humanCombined(before, after string) string {
	if before == "FAILED" || after == "FAILED" {
		return "FAILED"
	}
	if before != "PASS" || after != "PASS" {
		return "INCOMPLETE"
	}
	return "PASS"
}

func humanWorkload(value *workloadEvidence) (string, string) {
	if value == nil {
		return "Not recorded", "INCOMPLETE"
	}
	if value.Status == "failed" {
		return "Failed", "FAILED"
	}
	if value.Status != "passed" {
		return "Not confirmed", "INCOMPLETE"
	}
	switch value.Mode {
	case "http":
		if len(value.HTTP) == 0 {
			return "Missing HTTP evidence", "INCOMPLETE"
		}
		for _, check := range value.HTTP {
			if !check.Passed || check.Path == "" || check.Status < 200 || check.Status > 599 || check.ErrorCode != "" || !toolDigest(check.BodySHA256) {
				return "HTTP evidence incomplete", "INCOMPLETE"
			}
		}
		return fmt.Sprintf("%d HTTP checks passed", len(value.HTTP)), "PASS"
	case "batch":
		if value.ExitCode == nil || *value.ExitCode != 0 {
			return "Missing batch exit evidence", "INCOMPLETE"
		}
		label := "Original command passed"
		if value.CommandOverride {
			label = "Declared command passed"
		}
		return label, "PASS"
	default:
		return "Missing workload mode", "INCOMPLETE"
	}
}

func validHumanProbe(probe *genericProbeEvidence) bool {
	return probe != nil && probe.Version == "generic-containment-v1"
}

func humanIdentity(probe *genericProbeEvidence) string {
	if !validHumanProbe(probe) {
		return "Not recorded"
	}
	return fmt.Sprintf("%d:%d", probe.UID, probe.GID)
}

func humanWrites(probe *genericProbeEvidence, candidate bool) (string, string) {
	if !validHumanProbe(probe) || len(probe.ProtectedWrites) != 3 {
		return "Missing write evidence", "INCOMPLETE"
	}
	allowed, denied := 0, 0
	for _, write := range probe.ProtectedWrites {
		switch write.Status {
		case "allowed":
			allowed++
		case "denied":
			if write.ErrorCode == "EROFS" || write.ErrorCode == "EACCES" || write.ErrorCode == "EPERM" {
				denied++
			}
		}
	}
	status := "PASS"
	if allowed+denied != 3 {
		status = "INCOMPLETE"
	} else if candidate && allowed > 0 {
		status = "FAILED"
	}
	return fmt.Sprintf("%d allowed / %d denied", allowed, denied), status
}

func humanShells(probe *genericProbeEvidence) (string, string) {
	if !validHumanProbe(probe) || len(probe.Shells) != 13 {
		return "Missing shell evidence", "INCOMPLETE"
	}
	accessible, unknown := 0, 0
	for _, shell := range probe.Shells {
		switch shell.Status {
		case "accessible":
			accessible++
		case "unavailable", "denied":
		default:
			unknown++
		}
	}
	if unknown > 0 {
		return fmt.Sprintf("%d / 13; %d unknown", accessible, unknown), "INCOMPLETE"
	}
	return fmt.Sprintf("%d / 13", accessible), "PASS"
}

func humanInstall(probe *genericProbeEvidence, candidate bool) (string, string) {
	if !validHumanProbe(probe) {
		return "Not recorded", "INCOMPLETE"
	}
	install := probe.LocalToolInstall
	if install.Status == "allowed" {
		if candidate {
			return "Allowed", "FAILED"
		}
		return "Allowed", "PASS"
	}
	if install.Status == "denied" && (install.ErrorCode == "EROFS" || install.ErrorCode == "EACCES" || install.ErrorCode == "EPERM") && (install.Stage == "create_directory" || install.Stage == "create_file" || install.Stage == "copy_file") {
		return "Denied (protected write)", "PASS"
	}
	return "Not confirmed", "INCOMPLETE"
}
