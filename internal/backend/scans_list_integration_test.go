package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/goodnightsec/gn-check/internal/store"
	"github.com/goodnightsec/gn-check/internal/types"
)

func TestListScansFilterPaginationPostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := openScanRequestTestStore(t, ctx, dsn)

	suffix := types.NewID()[:8]
	targetA, err := st.CreateTarget(ctx, store.Target{Name: "scanlist-alpha-" + suffix, Hosts: []string{"alpha.invalid"}})
	if err != nil {
		t.Fatalf("target A: %v", err)
	}
	targetB, err := st.CreateTarget(ctx, store.Target{Name: "scanlist-beta-" + suffix, Hosts: []string{"beta.invalid"}})
	if err != nil {
		t.Fatalf("target B: %v", err)
	}
	ts, err := st.CreateTemplateSet(ctx, store.TemplateSet{Name: "scanlist-set-" + suffix, Mode: store.TemplateSetModeAll})
	if err != nil {
		t.Fatalf("template set: %v", err)
	}
	policy, err := st.CreateScanPolicy(ctx, store.ScanPolicy{Name: "scanlist-policy-" + suffix, TemplateSetID: ts.ID})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	next := time.Now().UTC().Add(time.Hour)
	sched, err := st.CreateSchedule(ctx, store.Schedule{
		Name: "scanlist-sched-" + suffix, ScanPolicyID: policy.ID, TargetID: targetA.ID,
		Cron: "0 * * * *", Timezone: "UTC", Enabled: true, NextRunAt: &next,
	})
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}

	spec := types.ScanSpec{Targets: targetA.Hosts, Templates: types.TemplateSelector{TemplateIDs: []string{"t"}, TemplatesCommit: "c"}}
	idA, err := st.CreateScan(ctx, spec, store.ScanLink{TargetID: targetA.ID, ScanPolicyID: policy.ID, ScheduleID: sched.ID, Source: "schedule"})
	if err != nil {
		t.Fatalf("scan A: %v", err)
	}
	idB, err := st.CreateScan(ctx, types.ScanSpec{Targets: targetB.Hosts}, store.ScanLink{TargetID: targetB.ID, ScanPolicyID: policy.ID})
	if err != nil {
		t.Fatalf("scan B: %v", err)
	}
	idC, err := st.CreateScan(ctx, types.ScanSpec{Targets: targetA.Hosts}, store.ScanLink{TargetID: targetA.ID})
	if err != nil {
		t.Fatalf("scan C: %v", err)
	}

	// Give B a started_at in the past via MarkRunning; leave A queued (no started_at).
	if ok, err := st.MarkRunning(ctx, idB, "node-scan-b"); err != nil || !ok {
		t.Fatalf("mark running B: ok=%v err=%v", ok, err)
	}

	t.Run("name target", func(t *testing.T) {
		rows, total, err := st.ListScans(ctx, store.ScanListFilter{Query: "alpha-" + suffix, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 2 {
			t.Fatalf("total=%d want 2 (A+C)", total)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[r.ID] = true
		}
		if !got[idA] || !got[idC] || got[idB] {
			t.Fatalf("rows=%v want A+C", got)
		}
	})

	t.Run("name policy", func(t *testing.T) {
		rows, total, err := st.ListScans(ctx, store.ScanListFilter{Query: "scanlist-policy-" + suffix, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 2 {
			t.Fatalf("total=%d want 2 (A+B share policy)", total)
		}
		_ = rows
	})

	t.Run("name schedule", func(t *testing.T) {
		rows, total, err := st.ListScans(ctx, store.ScanListFilter{Query: "scanlist-sched-" + suffix, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].ID != idA {
			t.Fatalf("got total=%d rows=%v want only A", total, rows)
		}
	})

	t.Run("id prefix", func(t *testing.T) {
		prefix := idB[:8]
		rows, total, err := st.ListScans(ctx, store.ScanListFilter{Query: prefix, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range rows {
			if r.ID == idB {
				found = true
			}
		}
		if !found || total < 1 {
			t.Fatalf("prefix %q did not match B (total=%d)", prefix, total)
		}
	})

	t.Run("like metachar escape", func(t *testing.T) {
		// A query of "%" alone would match everything if unescaped; with escape it
		// matches only names containing a literal percent (none here).
		_, total, err := st.ListScans(ctx, store.ScanListFilter{Query: "%", Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 0 {
			t.Fatalf("literal %% query total=%d, want 0", total)
		}
	})

	t.Run("started range includes queued via created_at", func(t *testing.T) {
		from := time.Now().UTC().Add(-time.Hour)
		to := time.Now().UTC().Add(time.Hour)
		rows, total, err := st.ListScans(ctx, store.ScanListFilter{StartedFrom: &from, StartedTo: &to, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[r.ID] = true
		}
		if total < 3 || !got[idA] || !got[idB] || !got[idC] {
			t.Fatalf("range total=%d got=%v want A+B+C", total, got)
		}
	})

	t.Run("started range past excludes recent", func(t *testing.T) {
		from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		to := time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC)
		_, total, err := st.ListScans(ctx, store.ScanListFilter{StartedFrom: &from, StartedTo: &to, Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 0 {
			t.Fatalf("past range total=%d want 0", total)
		}
	})

	t.Run("pagination envelope total", func(t *testing.T) {
		page1, total, err := st.ListScans(ctx, store.ScanListFilter{Query: "scanlist-alpha-" + suffix, Limit: 1, Offset: 0})
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if total != 2 || len(page1) != 1 {
			t.Fatalf("page1 len=%d total=%d", len(page1), total)
		}
		page2, total2, err := st.ListScans(ctx, store.ScanListFilter{Query: "scanlist-alpha-" + suffix, Limit: 1, Offset: 1})
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if total2 != 2 || len(page2) != 1 {
			t.Fatalf("page2 len=%d total=%d", len(page2), total2)
		}
		if page1[0].ID == page2[0].ID {
			t.Fatalf("pages returned same id %s", page1[0].ID)
		}
		// Newest first: page1 created_at >= page2
		if page1[0].CreatedAt.Before(page2[0].CreatedAt) {
			t.Fatalf("order not newest-first: %v then %v", page1[0].CreatedAt, page2[0].CreatedAt)
		}
	})

	// HTTP layer: envelope + 400s
	srv := NewServer(st, nil, nil, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	h := srv.Handler()

	t.Run("http envelope", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/scans?limit=2&offset=0&q=scanlist-alpha-"+suffix, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
		}
		var page scansPage
		if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if page.Total != 2 || len(page.Items) != 2 || page.Limit != 2 || page.Offset != 0 {
			t.Fatalf("page=%+v", page)
		}
	})

	t.Run("http 400 malformed", func(t *testing.T) {
		for _, path := range []string{
			"/api/scans?limit=nope",
			"/api/scans?offset=-3",
			"/api/scans?started_from=not-a-time",
			"/api/scans?limit=9999",
		} {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s status=%d want 400 body=%q", path, rr.Code, rr.Body.String())
			}
		}
	})
}
