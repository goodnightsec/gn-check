package backend

import (
	"net/url"
	"testing"

	"github.com/goodnightsec/gn-check/internal/store"
)

// FuzzParseScanListParams feeds arbitrary query strings to the GET /api/scans
// parser. It must never panic, and every filter it accepts must stay within
// the documented bounds.
func FuzzParseScanListParams(f *testing.F) {
	for _, seed := range []string{
		"",
		"q=alpha&limit=25&offset=50",
		"q=100%25&limit=1",
		"q=a_b&q=c",
		"limit=0",
		"limit=-1&offset=-1",
		"limit=99999999999999999999",
		"offset=9223372036854775808",
		"started_from=2026-01-01T00:00:00Z&started_to=2025-01-01T00:00:00Z",
		"started_from=not-a-time",
		"q=%5C%00%FF",
		"q=%zz",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		got, err := parseScanListParams(q)
		if err != nil {
			return
		}
		if got.Limit < 1 || got.Limit > store.MaxScanPageLimit {
			t.Fatalf("limit %d out of range for %q", got.Limit, raw)
		}
		if got.Offset < 0 {
			t.Fatalf("negative offset %d for %q", got.Offset, raw)
		}
		if len(got.Query) > store.MaxScanListQueryBytes {
			t.Fatalf("query of %d bytes accepted for %q", len(got.Query), raw)
		}
		if got.StartedFrom != nil && got.StartedTo != nil && got.StartedTo.Before(*got.StartedFrom) {
			t.Fatalf("inverted range accepted for %q", raw)
		}
	})
}
