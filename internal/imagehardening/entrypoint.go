// Package imagehardening provides the supplied-image hardening workflow and its
// bounded tool/containment commands without a second CLI process or module.
package imagehardening

import "io"

// Run dispatches hardening arguments (without the leading "harden") and writes
// structured results to out. It does not load .env or invoke a login UI.
func Run(args []string, out io.Writer) error {
	return harden(args, out)
}
