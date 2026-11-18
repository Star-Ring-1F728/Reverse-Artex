package contextactivation

import (
	"path/filepath"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
)

type Profile struct {
	Journal       string `json:"journal_path"`
	Policy        string `json:"production_policy_path"`
	CanaryProfile string `json:"canary_profile_path"`
}

func LoadProfile(path string) (Policy, contextrelease.Config, string, string, error) {
	var p Profile
	var policy Policy
	if e := contextshadow.ReadPublic(path, &p); e != nil {
		return policy, contextrelease.Config{}, "", "", e
	}
	resolve := func(v string) string {
		if v == "" {
			return ""
		}
		if filepath.IsAbs(v) {
			return filepath.Clean(v)
		}
		return filepath.Join(filepath.Dir(path), v)
	}
	if p.Journal == "" || p.Policy == "" || p.CanaryProfile == "" {
		return policy, contextrelease.Config{}, "", "", ErrInvalid
	}
	if e := contextshadow.ReadPublic(resolve(p.Policy), &policy); e != nil {
		return policy, contextrelease.Config{}, "", "", e
	}
	canary, e := filepath.Abs(resolve(p.CanaryProfile))
	if e != nil {
		return policy, contextrelease.Config{}, "", "", e
	}
	c, _, e := contextrelease.LoadProfile(canary)
	if e != nil || ValidatePolicy(policy, c) != nil {
		return policy, c, "", "", ErrInvalid
	}
	journal, e := filepath.Abs(resolve(p.Journal))
	return policy, c, journal, canary, e
}
