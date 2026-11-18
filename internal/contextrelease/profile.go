package contextrelease

import (
	"path/filepath"
	"reverse-artex/internal/contextshadow"
)

// Only the filesystem operator supplies paths. Web requests carry no paths,
// policies, keys or candidate packages.
type Profile struct {
	Journal         string `json:"journal_path"`
	ReleasePolicy   string `json:"release_policy_path"`
	AdmissionPolicy string `json:"admission_policy_path"`
	Authorities     string `json:"authority_trust_path"`
	ContextTrust    string `json:"context_trust_path"`
}

func LoadProfile(path string) (Config, string, error) {
	var p Profile
	var c Config
	if e := contextshadow.ReadPublic(path, &p); e != nil {
		return c, "", e
	}
	resolve := func(value string) string {
		if value == "" {
			return ""
		}
		if filepath.IsAbs(value) {
			return filepath.Clean(value)
		}
		return filepath.Join(filepath.Dir(path), value)
	}
	for _, input := range []struct {
		path  string
		value any
	}{{p.ReleasePolicy, &c.Policy}, {p.AdmissionPolicy, &c.Admission}, {p.Authorities, &c.Authorities}, {p.ContextTrust, &c.Context}} {
		if input.path == "" {
			return c, "", ErrInvalid
		}
		if e := contextshadow.ReadPublic(resolve(input.path), input.value); e != nil {
			return c, "", e
		}
	}
	if p.Journal == "" || ValidateConfig(c) != nil {
		return c, "", ErrInvalid
	}
	journal, e := filepath.Abs(resolve(p.Journal))
	return c, journal, e
}
