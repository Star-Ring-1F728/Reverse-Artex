// Package contextfeedback bridges replay-verified incident labels and signed
// observations to a new training batch. It never writes labels or predictions.
package contextfeedback

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/recovery"
	"sort"
	"time"
)

var id = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)
var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Annotation struct {
	CaseID      string `json:"case_id"`
	CaseSHA     string `json:"case_sha256"`
	Family      string `json:"family"`
	SourceGroup string `json:"source_group"`
}

type Request struct {
	Schema      string       `json:"schema"`
	Tenant      string       `json:"tenant_id"`
	DatasetID   string       `json:"dataset_id"`
	RecipeSHA   string       `json:"recipe_sha256"`
	Reviewer    string       `json:"reviewer_key_id"`
	Annotations []Annotation `json:"annotations"`
}

type Exclusion struct {
	CaseID string `json:"case_id"`
	Reason string `json:"reason"`
}

type Prepared struct {
	Schema            string                   `json:"schema"`
	Inputs            contextlearning.Inputs   `json:"inputs"`
	Gold              contextlearning.Gold     `json:"gold"`
	Review            contextlearning.Review   `json:"review_template"`
	Trust             casememory.LearningTrust `json:"review_trust"`
	SelectionSHA      string                   `json:"verified_selection_sha256"`
	RequestSHA        string                   `json:"preparation_request_sha256"`
	LabelSHA          []string                 `json:"current_label_sha256"`
	Planned           int                      `json:"planned"`
	Included          int                      `json:"included"`
	Attacks           int                      `json:"confirmed_attacks"`
	Benign            int                      `json:"confirmed_benign"`
	Unresolved        int                      `json:"unresolved"`
	Exclusions        []Exclusion              `json:"exclusions"`
	ReadyForReview    bool                     `json:"ready_for_review"`
	DeploymentAllowed bool                     `json:"deployment_allowed"`
	SHA               string                   `json:"preparation_sha256"`
}

func PreparationSHA(p Prepared) string { p.SHA = ""; return contextlearning.Digest(p) }

func reviewedUnresolved(v casememory.View, trust casememory.LearningTrust) bool {
	if !v.LabelCurrent || len(v.Labels) == 0 {
		return false
	}
	l := v.Labels[len(v.Labels)-1]
	if (l.Value != "uncertain" && l.Value != "disputed") || l.Verification == nil || l.CaseSHA != v.Current.SHA {
		return false
	}
	q := l.Verification.Statement
	for _, k := range trust.Keys {
		if k.ID != q.KeyID || k.Role != "label_reviewer" || k.Actor != l.Actor || k.Revoked {
			continue
		}
		pub, a := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		sig, b := base64.StdEncoding.Strict().DecodeString(q.Signature)
		return a == nil && b == nil && len(pub) == 32 && len(sig) == 64 && ed25519.Verify(pub, casememory.LabelSigningBytes(q), sig)
	}
	return false
}

// Prepare requires a stopped collector or an immutable snapshot and an owned,
// replay-verified case journal. Family/source metadata is supplied for reviewer
// approval; it is not inferred from a denial or a classifier prediction.
func Prepare(snapshot *evidence.Snapshot, memory *casememory.Store, trust actioncontext.Trust, q Request, now time.Time) (Prepared, error) {
	if snapshot == nil || memory == nil || now.IsZero() || q.Schema != "case-context-feedback-request/1" || !id.MatchString(q.Tenant) || !id.MatchString(q.DatasetID) || !pin.MatchString(q.RecipeSHA) || len(q.Annotations) == 0 || len(q.Annotations) > 512 || trust.Validate() != nil || recovery.VerifySnapshot(snapshot) != nil {
		return Prepared{}, contextlearning.ErrInvalid
	}
	var meta recovery.Metadata
	if json.Unmarshal(snapshot.Metadata(), &meta) != nil || meta.ContextTrust == nil || contextlearning.Digest(*meta.ContextTrust) != contextlearning.Digest(trust) {
		return Prepared{}, contextlearning.ErrInvalid
	}
	authorities, err := memory.LearningTrust(q.Tenant)
	if err != nil {
		return Prepared{}, err
	}
	reviewer := false
	for _, k := range authorities.Keys {
		reviewer = reviewer || k.ID == q.Reviewer && k.Role == "label_reviewer" && !k.Revoked
	}
	if !reviewer {
		return Prepared{}, contextlearning.ErrInvalid
	}
	selection, err := memory.SelectVerified(q.Tenant, false)
	if err != nil || selection.TrustSHA != casememory.LearningTrustDigest(authorities) {
		return Prepared{}, contextlearning.ErrInvalid
	}
	manifest, err := incident.Build(snapshot)
	if err != nil {
		return Prepared{}, err
	}
	cases := map[string]incident.Case{}
	for _, c := range manifest.Cases {
		if c.Tenant == q.Tenant {
			cases[c.ID] = c
		}
	}
	annotations := map[string]Annotation{}
	for _, a := range q.Annotations {
		c, ok := cases[a.CaseID]
		if !ok || a.CaseSHA != contextlearning.Digest(c) || !id.MatchString(a.Family) || !id.MatchString(a.SourceGroup) || annotations[a.CaseID].CaseID != "" {
			return Prepared{}, contextlearning.ErrInvalid
		}
		annotations[a.CaseID] = a
	}
	p := Prepared{Schema: "case-context-feedback-preparation/1", Trust: authorities, SelectionSHA: selection.SHA, RequestSHA: contextlearning.Digest(q), LabelSHA: []string{}, Planned: selection.Total, Exclusions: []Exclusion{}}
	p.Inputs = contextlearning.Inputs{Schema: contextlearning.Schema, Purpose: "training", DatasetID: q.DatasetID, Tenant: q.Tenant, SourceSHA: snapshot.SHA256(), ContextTrustSHA: contextlearning.Digest(trust), CreatedAt: now, RecipeSHA: q.RecipeSHA, Rows: []contextlearning.Row{}}
	p.Gold = contextlearning.Gold{Schema: "case-context-gold/2", DatasetID: q.DatasetID, Rows: []contextlearning.GoldRow{}}
	selected, values := []incident.Case{}, map[string]string{}
	remembered := map[string]bool{}
	for _, item := range selection.Items {
		remembered[item.CaseID] = true
		view, err := memory.Get(q.Tenant, item.CaseID)
		if err != nil {
			return Prepared{}, err
		}
		reason := item.Exclusion
		if (reason == "uncertain" || reason == "disputed") && reviewedUnresolved(view, authorities) {
			reason = ""
		}
		c, ok := cases[item.CaseID]
		if reason == "" && (!ok || contextlearning.Digest(c) != item.CaseSHA) {
			reason = "case_not_current_in_snapshot"
		}
		if reason == "" && annotations[item.CaseID].CaseID == "" {
			reason = "missing_family_source_annotation"
		}
		if reason != "" {
			p.Exclusions = append(p.Exclusions, Exclusion{item.CaseID, reason})
			continue
		}
		selected, values[c.ID] = append(selected, c), item.Label
		p.LabelSHA = append(p.LabelSHA, item.LabelSHA)
	}
	for caseID := range cases {
		if !remembered[caseID] {
			p.Planned++
			p.Exclusions = append(p.Exclusions, Exclusion{caseID, "not_synced_in_case_memory"})
		}
	}
	sort.Slice(p.Exclusions, func(i, j int) bool { return p.Exclusions[i].CaseID < p.Exclusions[j].CaseID })
	if len(selected) == 0 {
		return Prepared{}, contextlearning.ErrInvalid
	}
	rows, err := contextlearning.Extract(snapshot, selected, trust)
	if err != nil {
		return Prepared{}, err
	}
	families, groups := map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		a := annotations[row.ID]
		row.Family, row.SourceGroup = a.Family, a.SourceGroup
		p.Inputs.Rows = append(p.Inputs.Rows, row)
		p.Gold.Rows = append(p.Gold.Rows, contextlearning.GoldRow{ID: row.ID, Value: values[row.ID]})
		switch values[row.ID] {
		case "confirmed_attack":
			p.Attacks++
		case "confirmed_benign":
			p.Benign++
		default:
			p.Unresolved++
		}
		families[a.Family], groups[a.SourceGroup] = true, true
	}
	p.Included = len(rows)
	sort.Strings(p.LabelSHA)
	p.ReadyForReview = p.Attacks >= 30 && p.Benign >= 30 && len(families) >= 3 && len(groups) >= 3
	p.Review = contextlearning.Review{Schema: "case-context-fit-review/2", Tenant: q.Tenant, TrustSHA: selection.TrustSHA, InputsSHA: contextlearning.Digest(p.Inputs), GoldSHA: contextlearning.Digest(p.Gold), KeyID: q.Reviewer, IssuedAt: now}
	current, err := memory.SelectVerified(q.Tenant, false)
	if err != nil || current.SHA != selection.SHA {
		return Prepared{}, casememory.ErrConflict
	}
	p.SHA = PreparationSHA(p)
	return p, nil
}
