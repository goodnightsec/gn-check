package backend

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// uuidIDResources are the /api/<resource>/{id} routes whose {id} is a UUID
// column. Findings and occurrences parse their bigint id in the handler;
// templates and sessions use text ids.
var uuidIDResources = map[string]bool{
	"scans":            true,
	"targets":          true,
	"nodes":            true,
	"schedules":        true,
	"scan-policies":    true,
	"template-sets":    true,
	"service-accounts": true,
}

// validPathID reports whether the request's {id} is well formed for its route.
// requireRole and mutation check it before the handler runs, so a malformed
// UUID is a 400 instead of a Postgres cast error that surfaces as a 500 and an
// ERROR log line (SQLSTATE 22P02). Only the canonical 36-character form is
// accepted: the API only ever hands out that form.
func validPathID(r *http.Request) bool {
	_, path, ok := strings.Cut(r.Pattern, " ")
	if !ok {
		path = r.Pattern
	}
	seg := strings.Split(path, "/")
	if len(seg) < 4 || seg[3] != "{id}" || !uuidIDResources[seg[2]] {
		return true
	}
	id := r.PathValue("id")
	return len(id) == 36 && uuid.Validate(id) == nil
}
