package responsev2

import (
	"context"
	"errors"
	"reverse-artex/internal/decisions"
	"sort"
	"time"
)

const policyInstallCommandLimit = 4096

func (s *Store) Apply(ctx context.Context, tenant string, i Intent) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(ctx, tenant, i, time.Now())
}
func (s *Store) applyLocked(ctx context.Context, tenant string, i Intent, now time.Time) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := s.check(now); err != nil {
		return Receipt{}, err
	}
	if i.ID == "" || len(i.ID) > 128 || i.Run == "" || len(i.Run) > 128 || (i.Owner != "operator" && i.Owner != "native" && i.Owner != "decisions" && i.Owner != "l3") {
		return Receipt{}, ErrStale
	}
	// Receipt replay must retain its original tenant boundary even when the
	// case revision/epoch has since changed. Historical idempotency is a read,
	// not authority to disclose another tenant's prior policy receipt.
	if c, ok := s.cases[i.CaseID]; !ok || c.Tenant != tenant {
		return Receipt{}, ErrStale
	}
	if digest, ok := s.intents[i.ID]; ok {
		if digest != decisions.Hash(i) {
			return Receipt{}, ErrStale
		}
		return s.receipts[i.ID], nil
	}
	if s.paused || i.Epoch != s.epoch || len(s.intents) >= policyInstallCommandLimit {
		return Receipt{}, ErrStale
	}
	v, err := s.viewLocked(tenant, i.CaseID, now)
	if err != nil || v.Case.SHA != i.CaseSHA {
		return Receipt{}, ErrStale
	}
	var chosen *Candidate
	for _, c := range v.Candidates {
		if c.ID == i.CandidateID {
			x := c
			chosen = &x
		}
	}
	if chosen == nil {
		return Receipt{}, ErrStale
	}
	event := s.events[chosen.EvidenceID]
	key := scopeID(chosen.Scope)
	l, exists := s.leases[key]
	l = clone(l)
	if exists && now.Before(l.Cooldown) && (!now.Before(l.Expires) || len(l.Claims) == 0) {
		return Receipt{}, errors.New("scope cooldown active")
	}
	if !exists || !now.Before(l.Cooldown) {
		if !exists && len(s.leases) >= 1024 {
			return Receipt{}, ErrLimit
		}
		tenantCount := 0
		for _, p := range s.leases {
			if p.Scope.Tenant == tenant && now.Before(p.Cooldown) {
				tenantCount++
			}
		}
		if tenantCount >= 128 {
			return Receipt{}, ErrLimit
		}
		l = Lease{Schema: "policy-lease/2", ID: key, Scope: chosen.Scope, Episode: decisions.Hash([]any{key, event.Request, now.UTC()}), Issued: now.UTC(), Expires: event.At.Add(time.Minute), HardEnd: now.Add(2 * time.Minute).UTC(), Cooldown: now.Add(3 * time.Minute).UTC(), LastViolation: event.At, Generation: l.Generation + 1, Claims: []Claim{}, Consumed: []string{}}
	}
	consumed := false
	for _, r := range l.Consumed {
		consumed = consumed || r == event.Request
	}
	// New independent, later violations alone may extend the existing episode.
	if exists && !consumed && event.At.After(l.LastViolation) {
		expiry := event.At.Add(time.Minute)
		if expiry.After(l.HardEnd) {
			expiry = l.HardEnd
		}
		if expiry.After(l.Expires) {
			l.Expires = expiry
		}
		l.LastViolation = event.At
	}
	if !consumed {
		if len(l.Consumed) >= 128 {
			return Receipt{}, ErrLimit
		}
		l.Consumed = append(l.Consumed, event.Request)
	}
	found := false
	for n, claim := range l.Claims {
		if claim.Owner == i.Owner && claim.Run == i.Run {
			found = true
			l.Claims[n].Expires = l.Expires
		}
	}
	if consumed && found {
		receipt := Receipt{Intent: i.ID, PolicyID: l.ID, Generation: l.Generation, State: "already_installed_locally", Expires: l.Expires, Effect: "unknown; duplicate evidence has no added effect"}
		if err = s.commit(record{Operation: "consume-and-install", Intent: &i, Receipt: &receipt}); err != nil {
			return Receipt{}, err
		}
		return receipt, nil
	}
	if !found {
		if len(l.Claims) >= 4 {
			return Receipt{}, ErrLimit
		}
		l.Claims = append(l.Claims, Claim{Owner: i.Owner, Run: i.Run, Intent: i.ID, Expires: l.Expires})
	}
	if !l.Expires.After(now) {
		return Receipt{}, ErrStale
	}
	l.Generation++
	receipt := Receipt{Intent: i.ID, PolicyID: l.ID, Generation: l.Generation, State: "installed_locally", Expires: l.Expires, Effect: "unknown; local installation is not observed effect"}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err = s.commit(record{At: now.UTC(), Operation: "consume-and-install", Intent: &i, Lease: &l, Receipt: &receipt}); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}
func (s *Store) Release(ctx context.Context, tenant, id, owner, run, intent string, generation int) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseLocked(ctx, tenant, id, owner, run, intent, generation, time.Now())
}
func (s *Store) releaseLocked(ctx context.Context, tenant, id, owner, run, intent string, generation int, now time.Time) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := s.check(now); err != nil {
		return Receipt{}, err
	}
	commandSHA := decisions.Hash([]any{"release-owned-claim", tenant, id, owner, run, intent, generation})
	if intent == "" || len(intent) > 128 {
		return Receipt{}, ErrStale
	}
	if digest, ok := s.intents[intent]; ok {
		if digest != commandSHA {
			return Receipt{}, ErrStale
		}
		return s.receipts[intent], nil
	}
	// A new release consumes an existing claim. Each claim required an
	// admitted install, so releases remain bounded after installs stop.
	l, ok := s.leases[id]
	l = clone(l)
	if !ok || l.Scope.Tenant != tenant || l.Generation != generation || !l.Expires.After(now) {
		return Receipt{}, ErrStale
	}
	kept := []Claim{}
	found := false
	for _, c := range l.Claims {
		if c.Owner == owner && c.Run == run {
			found = true
		} else {
			if c.Expires.After(now) {
				kept = append(kept, c)
			}
		}
	}
	if !found {
		return Receipt{}, ErrStale
	}
	l.Claims = kept
	l.Generation++
	state := "retained_by_other_owner"
	if len(kept) == 0 {
		l.Expires = now.UTC()
		state = "no_effective_policy"
	} else {
		l.Expires = kept[0].Expires
		for _, c := range kept {
			if c.Expires.After(l.Expires) {
				l.Expires = c.Expires
			}
		}
	}
	r := Receipt{Intent: intent, PolicyID: l.ID, Generation: l.Generation, State: state, Expires: l.Expires, Effect: "recovery unobserved"}
	if err := s.commit(record{Operation: "release-owned-claim", At: now.UTC(), Lease: &l, Receipt: &r, CommandID: intent, CommandSHA: commandSHA}); err != nil {
		return Receipt{}, err
	}
	return r, nil
}
func (s *Store) Pause(paused bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	epoch := s.epoch + 1
	return s.commit(record{Operation: "cancel-epoch", Epoch: &epoch, Paused: &paused})
}
func (s *Store) Epoch() int { s.mu.Lock(); defer s.mu.Unlock(); return s.epoch }
func (s *Store) Policies(tenant string) []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Lease{}
	now := time.Now()
	for _, l := range s.leases {
		if l.Scope.Tenant == tenant && l.Expires.After(now) && now.Before(s.deadlines[l.ID]) && len(l.Claims) > 0 {
			out = append(out, clone(l))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Native coalesces redundant renewals on already covered exact scopes. This
// avoids exhausting the episode's consumed-evidence budget during a burst.
// Idle expiry may precede the newest violation's one-minute window by at most
// this interval; the two-minute hard end and cooldown remain unchanged.
const nativeRenewalInterval = 5 * time.Second

func (s *Store) Native(tenant, id, sha string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nativeLocked(tenant, id, sha, time.Now())
}

func (s *Store) nativeLocked(tenant, id, sha string, now time.Time) error {
	if err := s.check(now); err != nil {
		return err
	}
	v, err := s.viewLocked(tenant, id, now)
	if err != nil || v.Case.SHA != sha {
		return ErrStale
	}
	for _, c := range v.Candidates {
		if s.nativeCoveredLocked(c, now) {
			continue
		}
		_, err = s.applyLocked(context.Background(), tenant, Intent{ID: "native-" + decisions.Hash([]string{id, sha, c.ID})[:48], CaseID: id, CaseSHA: sha, CandidateID: c.ID, Owner: "native", Run: "native-v2", Epoch: s.epoch}, now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) nativeCoveredLocked(c Candidate, now time.Time) bool {
	l, ok := s.leases[scopeID(c.Scope)]
	if !ok || l.Scope != c.Scope || !now.Before(l.Expires) || !now.Before(s.deadlines[l.ID]) {
		return false
	}
	for _, claim := range l.Claims {
		if claim.Owner != "native" || claim.Run != "native-v2" || !now.Before(claim.Expires) {
			continue
		}
		desired := s.events[c.EvidenceID].At.Add(time.Minute)
		if desired.After(l.HardEnd) {
			desired = l.HardEnd
		}
		covered := l.Expires
		if claim.Expires.Before(covered) {
			covered = claim.Expires
		}
		return !desired.After(covered.Add(nativeRenewalInterval))
	}
	return false
}
