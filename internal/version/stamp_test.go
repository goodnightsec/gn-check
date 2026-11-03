package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stampLdflags is the -ldflags value both image builds pass to go build.
const stampLdflags = `-ldflags "-X github.com/goodnightsec/gn-check/internal/version.versionTag=${VERSION_TAG} -X github.com/goodnightsec/gn-check/internal/version.gitCommit=${commit}"`

// TestImagesStampTheSameIdentity keeps the backend and scanner image builds in
// step: both declare the release build args, resolve the commit the same way,
// and link it into their binary.
func TestImagesStampTheSameIdentity(t *testing.T) {
	for _, name := range []string{"Dockerfile.backend", "Dockerfile.scanner"} {
		t.Run(name, func(t *testing.T) {
			body := readRepoFile(t, "deploy", name)
			for _, want := range []string{
				"ARG VERSION_TAG=",
				"ARG GIT_COMMIT=",
				"sh deploy/resolve_git_commit.sh .git",
				stampLdflags,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("%s lacks %q", name, want)
				}
			}
		})
	}
}

// TestReleaseImagesLicenseLabel checks that the release workflow sets the
// project's SPDX license expression instead of the one GitHub detects.
func TestReleaseImagesLicenseLabel(t *testing.T) {
	body := readRepoFile(t, ".github", "workflows", "release.yml")
	if !strings.Contains(body, "org.opencontainers.image.licenses=AGPL-3.0-or-later") {
		t.Error("release.yml does not set org.opencontainers.image.licenses=AGPL-3.0-or-later")
	}
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
