package backend

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every route with a UUID {id} answers a malformed id with 400 before the
// handler runs. The server has no store, so a request that got through to a
// handler would panic instead of returning 400.
func TestMalformedUUIDPathIDIsBadRequest(t *testing.T) {
	routes := []string{
		"GET /api/scans/123",
		"POST /api/scans/123/cancel",
		"DELETE /api/scans/123",
		"GET /api/scans/123/findings",
		"GET /api/scans/123/raw",
		"GET /api/scans/123/log",
		"GET /api/scans/123/export",
		"GET /api/targets/123",
		"PUT /api/targets/123",
		"DELETE /api/targets/123",
		"GET /api/nodes/123",
		"PUT /api/nodes/123",
		"DELETE /api/nodes/123",
		"POST /api/nodes/123/templates/sync",
		"GET /api/schedules/123",
		"PUT /api/schedules/123",
		"POST /api/schedules/123/run",
		"DELETE /api/schedules/123",
		"GET /api/scan-policies/123",
		"PUT /api/scan-policies/123",
		"DELETE /api/scan-policies/123",
		"GET /api/template-sets/123",
		"GET /api/template-sets/123/export",
		"PUT /api/template-sets/123",
		"DELETE /api/template-sets/123",
		"GET /api/template-sets/123/members",
		"PUT /api/template-sets/123/members",
		"POST /api/template-sets/123/members",
		"DELETE /api/template-sets/123/members/x",
		"GET /api/template-sets/123/exclusions",
		"PUT /api/template-sets/123/exclusions",
		"POST /api/service-accounts/123/rotate",
		"DELETE /api/service-accounts/123",
	}
	var logs bytes.Buffer
	srv := NewServer(nil, nil, nil, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(&logs, nil)), t.TempDir())
	h := srv.Handler()
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body = %s", route, rec.Code, rec.Body.String())
		}
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("malformed ids logged an ERROR:\n%s", logs.String())
	}
}

func TestValidPathID(t *testing.T) {
	cases := []struct {
		pattern, id string
		want        bool
	}{
		{"GET /api/targets/{id}", "0b9c5c8e-2f43-4a8e-9a4b-2f5d3c1e7a10", true},
		{"GET /api/targets/{id}", "0B9C5C8E-2F43-4A8E-9A4B-2F5D3C1E7A10", true},
		{"GET /api/targets/{id}", "123", false},
		{"GET /api/targets/{id}", "0b9c5c8e2f434a8e9a4b2f5d3c1e7a10", false},
		{"GET /api/targets/{id}", "urn:uuid:0b9c5c8e-2f43-4a8e-9a4b-2f5d3c1e7a10", false},
		{"DELETE /api/template-sets/{id}/members/{templateId}", "zap", false},
		// Not UUID columns: the handler or the store decides.
		{"GET /api/findings/{id}", "abc", true},
		{"GET /api/templates/{id}", "http-missing-security-headers", true},
		{"DELETE /api/sessions/{id}", "abc", true},
		{"GET /api/targets", "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Pattern = c.pattern
		r.SetPathValue("id", c.id)
		if got := validPathID(r); got != c.want {
			t.Errorf("validPathID(%q, %q) = %v, want %v", c.pattern, c.id, got, c.want)
		}
	}
}
