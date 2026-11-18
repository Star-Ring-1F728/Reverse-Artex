package edge

import (
	"io"
	"net/http"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/routecoverage"
	"time"
)

// Apply the optional inventory before the SDK or application gets any request.
// A synchronized local audit is required even for explicit app exceptions.
func coverageAdmission(c Config, w http.ResponseWriter, r *http.Request, started time.Time) (string, bool) {
	if c.Coverage == nil {
		return "", false
	}
	id, err := identity.NewRequestID(c.Now(), c.TimeOrderedRequestID)
	status := 0
	if err != nil || c.Protection == nil || c.Coverage.Policy() == nil || c.Coverage.Policy().RegistryDigest() != c.Protection.Digest() || c.Coverage.Policy().Asset() != c.Asset || len(c.HMACKey) < 32 {
		status = 503
	}
	var d routecoverage.Decision
	if status == 0 {
		d = c.Coverage.Decide(r.URL, r.Method)
		if c.Coverage.Record(d, id, r.Method, identity.Pseudonym(r.URL.Path, c.HMACKey), r.URL.RawQuery != "" || r.URL.ForceQuery, c.Now()) != nil {
			status = 503
		} else {
			status = d.Status
		}
	}
	if status == 0 {
		now := c.Now()
		if now.Before(started) || now.Sub(started) >= protection.ProofLifetime || r.Context().Err() != nil {
			status = 503
		}
	}
	if status == 0 && d.Class != routecoverage.Local {
		return id, false
	}
	if r.Body != nil && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", id)
	if status == 0 {
		status = 200
	}
	if r.Method == "HEAD" {
		w.WriteHeader(status)
	} else if status == 200 {
		w.WriteHeader(status)
	} else {
		http.Error(w, http.StatusText(status), status)
	}
	return id, true
}
