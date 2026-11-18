package responsev2

import (
	"sort"
	"time"
)

// Only completed response facts are folded. In-flight responses remain exact
// attempts, and future policy installations cannot include earlier sequences.
type outcomeRef struct {
	ID       string `json:"attempt_id"`
	Sequence int    `json:"prepared_sequence"`
	Ordinal  int    `json:"ordinal"`
}
type outcomeTally struct {
	Count int          `json:"count"`
	Refs  []outcomeRef `json:"refs"`
}
type outcomeFacts struct {
	Target          outcomeTally `json:"target"`
	Benign          outcomeTally `json:"benign"`
	Recovery        outcomeTally `json:"recovery"`
	Collateral      bool         `json:"collateral"`
	BenignObserved  bool         `json:"benign_observed"`
	TargetRecovered bool         `json:"target_recovered"`
	BenignRecovered bool         `json:"benign_recovered"`
	Unknown         int          `json:"unknown"`
}
type outcomeWindow struct {
	endSequence int
	nextEpisode int
	endAt       time.Time
	reason      string
}

func (t *outcomeTally) add(a ResponseAttempt, ordinal int) {
	t.Count++
	t.Refs = append(t.Refs, outcomeRef{a.ID, a.PreparedSequence, ordinal})
	sort.Slice(t.Refs, func(i, j int) bool {
		if t.Refs[i].Sequence != t.Refs[j].Sequence {
			return t.Refs[i].Sequence < t.Refs[j].Sequence
		}
		return t.Refs[i].Ordinal < t.Refs[j].Ordinal
	})
	if len(t.Refs) > 8 {
		t.Refs = t.Refs[:8]
	}
}
func (t outcomeTally) axis(state string) OutcomeAxis {
	refs := make([]string, 0, len(t.Refs))
	for _, r := range t.Refs {
		refs = append(refs, r.ID)
	}
	return OutcomeAxis{State: state, Count: t.Count, Refs: refs}
}
func cloneOutcomeFacts(f outcomeFacts) outcomeFacts {
	f.Target.Refs = append([]outcomeRef(nil), f.Target.Refs...)
	f.Benign.Refs = append([]outcomeRef(nil), f.Benign.Refs...)
	f.Recovery.Refs = append([]outcomeRef(nil), f.Recovery.Refs...)
	return f
}
func (s *Store) outcomeWindowLocked(h PolicyHistory, now time.Time) outcomeWindow {
	w := outcomeWindow{endAt: h.Latest.Expires}
	for _, r := range h.Releases {
		if r.State == "no_effective_policy" {
			w.endSequence = r.Sequence
			w.endAt = r.At
			w.reason = "explicit_last_claim_release"
		}
	}
	if w.reason == "" && !now.Before(h.Latest.Expires) {
		w.reason = "natural_expiry"
	}
	for _, other := range s.histories {
		if other.Binding.PolicyID == h.Binding.PolicyID && other.InstalledSequence > h.InstalledSequence && (w.nextEpisode == 0 || other.InstalledSequence < w.nextEpisode) {
			w.nextEpisode = other.InstalledSequence
		}
	}
	return w
}
func (f *outcomeFacts) include(h PolicyHistory, window outcomeWindow, a ResponseAttempt, e Evidence, obs *ResponseObservation) {
	if (window.nextEpisode > 0 && a.PreparedSequence >= window.nextEpisode) || a.PreparedSequence < h.InstalledSequence || a.Scope.Tenant != h.Binding.Scope.Tenant || a.Scope.Asset != h.Binding.Scope.Asset {
		return
	}
	sameActor := a.Scope.Principal == h.Binding.Scope.Principal && a.Scope.Session == h.Binding.Scope.Session
	target := a.Scope == h.Binding.Scope
	owned := a.PolicyID == h.Binding.PolicyID && a.Episode == h.Binding.Episode
	if obs == nil || !obs.Write.Complete || obs.Write.Error {
		if owned || target {
			f.Unknown++
		}
		return
	}
	write := obs.Write
	if owned {
		if write.Status == 429 && a.SDKStatus == 403 {
			f.Target.add(a, 0)
		}
		if write.Status == 429 && a.SDKStatus == 200 {
			f.Collateral = true
			f.Benign.add(a, 0)
		}
		if write.Status != a.PlannedStatus {
			f.Unknown++
		}
	}
	exact := write.Bytes == e.BodyLength && write.BodySHA == e.BodySHA
	if sameActor && a.SDKStatus == 200 && write.Status == 200 && exact && (a.PreparedAt.Before(window.endAt) || window.reason == "") {
		f.BenignObserved = true
		f.Benign.add(a, 0)
	}
	after := window.reason != "" && !a.PreparedAt.Before(window.endAt) && (window.endSequence == 0 || a.PreparedSequence > window.endSequence)
	if after && target && a.PolicyID == "" && (a.SDKStatus == 200 || a.SDKStatus == 403) && write.Status == a.SDKStatus && exact {
		f.TargetRecovered = true
		f.Recovery.add(a, 0)
	}
	if after && sameActor && a.PolicyID == "" && a.SDKStatus == 200 && write.Status == 200 && exact {
		f.BenignRecovered = true
		f.Recovery.add(a, 1)
	}
}
