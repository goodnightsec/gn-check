package backend

import (
	"net/url"
	"testing"
	"time"

	"github.com/goodnightsec/gn-check/internal/store"
)

func TestParseScanListParamsDefaults(t *testing.T) {
	f, err := parseScanListParams(url.Values{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if f.Limit != store.DefaultScanPageLimit || f.Offset != 0 || f.Query != "" || f.StartedFrom != nil || f.StartedTo != nil {
		t.Fatalf("defaults = %+v", f)
	}
}

func TestParseScanListParamsValid(t *testing.T) {
	q := url.Values{}
	q.Set("q", "Acme")
	q.Set("limit", "25")
	q.Set("offset", "50")
	q.Set("started_from", "2026-01-01T00:00:00Z")
	q.Set("started_to", "2026-01-31T23:59:59Z")
	f, err := parseScanListParams(q)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if f.Query != "Acme" || f.Limit != 25 || f.Offset != 50 {
		t.Fatalf("got %+v", f)
	}
	if f.StartedFrom == nil || !f.StartedFrom.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("started_from = %v", f.StartedFrom)
	}
	if f.StartedTo == nil || !f.StartedTo.Equal(time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)) {
		t.Fatalf("started_to = %v", f.StartedTo)
	}
}

func TestParseScanListParamsInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"limit non-int", "limit=abc"},
		{"limit zero", "limit=0"},
		{"limit negative", "limit=-1"},
		{"limit over max", "limit=501"},
		{"offset non-int", "offset=x"},
		{"offset negative", "offset=-1"},
		{"started_from bad", "started_from=yesterday"},
		{"started_to bad", "started_to=2026-01-01"},
		{"range inverted", "started_from=2026-02-01T00:00:00Z&started_to=2026-01-01T00:00:00Z"},
		{"duplicate q", "q=a&q=b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, err := url.ParseQuery(tc.raw)
			if err != nil {
				t.Fatalf("ParseQuery: %v", err)
			}
			if _, err := parseScanListParams(vals); err == nil {
				t.Fatalf("expected error for %q", tc.raw)
			}
		})
	}
}

func TestParseScanListParamsQueryCap(t *testing.T) {
	q := url.Values{}
	q.Set("q", string(make([]byte, store.MaxScanListQueryBytes+1)))
	if _, err := parseScanListParams(q); err == nil {
		t.Fatal("expected oversized q error")
	}
}

func TestParseScanListParamsRFC3339Nano(t *testing.T) {
	q := url.Values{}
	q.Set("started_from", "2026-01-01T00:00:00.123456789Z")
	f, err := parseScanListParams(q)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if f.StartedFrom == nil {
		t.Fatal("started_from nil")
	}
}
