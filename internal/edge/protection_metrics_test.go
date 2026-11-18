package edge

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/routecoverage"
	"testing"
)

func TestCoverageAndHandlerMetricsIncludeAuditRejection(t *testing.T) {
	c, _ := guardFixture(t)
	p, err := routecoverage.New(routecoverage.Manifest{Schema: "route-coverage/1", Asset: c.Asset, Revision: "c1", Registry: c.Protection.Digest()}, c.Protection)
	if err != nil {
		t.Fatal(err)
	}
	c.ProtectionMetrics = &ProtectionMetrics{}
	audits := 0
	c.Coverage = routecoverage.NewGate(p, func(routecoverage.Observation) error { audits++; return errors.New("audit unavailable") })
	c.Transport = transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("audit failure reached upstream")
		return nil, nil
	})
	w := httptest.NewRecorder()
	Handler(c).ServeHTTP(w, httptest.NewRequest("GET", "/legacy/objects/one", nil))
	if w.Code != 503 || audits != 1 {
		t.Fatal("metrics changed coverage rejection", w.Code, audits)
	}
	stages := c.ProtectionMetrics.Snapshot()["stages"].(map[string]any)
	for _, stage := range []string{"handler_total", "coverage_admission"} {
		if stages[stage].(map[string]any)["count"] != uint64(1) {
			t.Fatal("unprotected timing gap", stage)
		}
	}
	if stages["total"].(map[string]any)["count"] != uint64(0) {
		t.Fatal("rejected coverage reached protected path")
	}
}
