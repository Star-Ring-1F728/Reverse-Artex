package responsev2

import (
	"time"
	"unicode/utf8"
)

// This opt-in contract bounds what a classification may assert about sampled
// verified facts. It is not an intent detector, policy decision or prose repair.
const l3GroundingScheme = "l3-evidence-grounding/1"

type l3GroundingCounts struct {
	Total                   int `json:"total"`
	Current                 int `json:"current"`
	Historical              int `json:"historical"`
	Future                  int `json:"future"`
	CurrentAuthorized       int `json:"current_authorized"`
	CurrentDenied           int `json:"current_denied"`
	CurrentUnknown          int `json:"current_unknown"`
	DistinctDeniedResources int `json:"distinct_current_denied_resources"`
	MixedCurrentResources   int `json:"mixed_current_status_resources"`
}

type l3Grounding struct {
	Schema           string            `json:"schema"`
	ComputedAt       time.Time         `json:"computed_at"`
	FreshnessSeconds int               `json:"freshness_seconds"`
	Counts           l3GroundingCounts `json:"counts"`
	Admissible       []string          `json:"admissible_classifications"`
	Authority        string            `json:"authority"`
}

func l3EvidenceAge(observed, now time.Time) (int64, string) {
	age := now.Sub(observed)
	state := "current"
	if age < 0 {
		state = "future"
	} else if age > 60*time.Second {
		state = "historical"
	}
	// This integer is a display precision only. Admission above uses the full
	// duration, including the exact60second boundary; timestamp is retained.
	return age.Milliseconds(), state
}

func l3EvidenceGrounding(view CaseView, now time.Time) l3Grounding {
	g := l3Grounding{Schema: l3GroundingScheme, ComputedAt: now.UTC(), FreshnessSeconds: 60,
		Admissible: []string{"needs_review", "insufficient_evidence"},
		Authority:  "sampled verified observations only; not actor intent, exposure, policy effect or authoritative model prose"}
	g.Counts.Total = len(view.Evidence)
	denied := map[string]bool{}
	statuses := map[string]map[int]bool{}
	for _, fact := range view.Evidence {
		_, state := l3EvidenceAge(fact.At, now)
		if state == "historical" {
			g.Counts.Historical++
			continue
		}
		if state == "future" {
			g.Counts.Future++
			continue
		}
		g.Counts.Current++
		resource := fact.Scope.Resource
		if statuses[resource] == nil {
			statuses[resource] = map[int]bool{}
		}
		statuses[resource][fact.Status] = true
		switch {
		case fact.Kind == "authorized_representation" && fact.Status == 200:
			g.Counts.CurrentAuthorized++
		case fact.Kind == "prevented_unauthorized_access" && fact.Status == 403:
			g.Counts.CurrentDenied++
			denied[resource] = true
		default:
			// Unknown503, authentication/missing-object context and malformed
			// kind/status combinations cannot authorize benign/suspicious.
			g.Counts.CurrentUnknown++
		}
	}
	g.Counts.DistinctDeniedResources = len(denied)
	for _, values := range statuses {
		if len(values) > 1 {
			g.Counts.MixedCurrentResources++
		}
	}
	completeCurrent := g.Counts.Total > 0 && g.Counts.Current == g.Counts.Total && g.Counts.CurrentUnknown == 0
	if completeCurrent && g.Counts.CurrentAuthorized == g.Counts.Total {
		g.Admissible = append(g.Admissible, "benign")
	} else if completeCurrent && g.Counts.CurrentDenied >= 2 && g.Counts.DistinctDeniedResources >= 2 && g.Counts.MixedCurrentResources == 0 {
		g.Admissible = append(g.Admissible, "suspicious")
	}
	return g
}

func l3ValidateGroundedAssessment(view CaseView, assessment L3Assessment, now time.Time) error {
	refs := map[string]bool{}
	for _, fact := range view.Evidence {
		refs[fact.ID] = true
	}
	if !utf8.ValidString(assessment.Summary) || !validAssessment(assessment, refs) {
		return ErrStale
	}
	g := l3EvidenceGrounding(view, now)
	allowed := false
	for _, value := range g.Admissible {
		allowed = allowed || assessment.Classification == value
	}
	if !allowed {
		return ErrStale
	}
	if assessment.Classification == "suspicious" {
		selected := map[string]bool{}
		for _, identifier := range assessment.Evidence {
			selected[identifier] = true
		}
		resources := map[string]bool{}
		for _, fact := range view.Evidence {
			_, state := l3EvidenceAge(fact.At, now)
			if selected[fact.ID] && state == "current" && fact.Kind == "prevented_unauthorized_access" && fact.Status == 403 {
				resources[fact.Scope.Resource] = true
			}
		}
		if len(resources) < 2 {
			return ErrStale
		}
	}
	return nil
}
