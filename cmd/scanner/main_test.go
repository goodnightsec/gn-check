package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerTokenOK(t *testing.T) {
	if scannerTokenOK("") {
		t.Error("empty token accepted")
	}
	if scannerTokenOK(strings.Repeat("a", minScannerTokenLen-1)) {
		t.Errorf("token below %d chars accepted", minScannerTokenLen)
	}
	if !scannerTokenOK(strings.Repeat("a", minScannerTokenLen)) {
		t.Errorf("token of exactly %d chars rejected", minScannerTokenLen)
	}
}

func TestResolveWorkDir(t *testing.T) {
	// Explicit value is honored as-is.
	if got, err := resolveWorkDir("/mnt/scans"); err != nil || got != "/mnt/scans" {
		t.Errorf("resolveWorkDir(explicit) = (%q, %v), want (/mnt/scans, nil)", got, err)
	}

	// Unset -> a private, process-exclusive dir with 0700 perms.
	dir, err := resolveWorkDir("")
	if err != nil {
		t.Fatalf("resolveWorkDir(\"\"): %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if dir == "/tmp/nuclei-scans" {
		t.Error("fell back to the predictable shared path")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("work dir perms = %o, want 0700", perm)
	}
}

// TestBinaryCarriesLinkStamp builds the scanner the way deploy/Dockerfile.scanner
// does and checks that the -X stamp lands in the binary. The linker ignores -X for
// a package the program does not link, so this fails if the scanner stops using
// internal/version and the release stamp silently disappears.
func TestBinaryCarriesLinkStamp(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the scanner binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	const (
		tag    = "v0.0.0-stamptest"
		commit = "0123456789abcdef0123456789abcdef01234567"
	)
	out := filepath.Join(t.TempDir(), "scanner")
	cmd := exec.Command(goBin, "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-X github.com/goodnightsec/gn-check/internal/version.versionTag="+tag+
			" -X github.com/goodnightsec/gn-check/internal/version.gitCommit="+commit,
		"-o", out, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, msg)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{tag, commit} {
		if !bytes.Contains(bin, []byte(want)) {
			t.Errorf("scanner binary does not contain the stamped %q", want)
		}
	}
}
