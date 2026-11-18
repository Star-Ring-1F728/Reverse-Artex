// action-simulation explicitly runs signed approval through a private local
// policy replica. It cannot connect to a real policy writer or arbitrary adapter.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"reverse-artex/internal/actionapproval"
	"reverse-artex/internal/actionproposal"
)

type probe struct {
	Name   string `json:"name"`
	Denied bool   `json:"denied"`
}
type report struct {
	Scope                   string                           `json:"scope"`
	ExternalPolicyMutations int                              `json:"external_policy_mutations"`
	ActualHostIsolation     bool                             `json:"actual_host_isolation"`
	Receipt                 actionapproval.SimulationReceipt `json:"receipt"`
	Probes                  []probe                          `json:"probes"`
}

func bounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() > limit {
		return nil, errors.New("bounded regular input required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("input byte limit")
	}
	return raw, nil
}
func alternate(value string) string {
	if value == "control-a" {
		return "control-b"
	}
	return "control-a"
}
func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("action-simulation", flag.ContinueOnError)
	f.SetOutput(stderr)
	enabled := f.Bool("simulation", false, "required explicit opt-in to local replica simulation only")
	state := f.String("state", "", "owned signed intent ledger path")
	trust := f.String("trust", "", "operator-pinned public key trust policy")
	auth := f.String("authorization", "", "signed approval; no signing/private-key loading here")
	input := f.String("request", "", "original proposal request")
	current := f.String("current", "", "locally declared current-case/configuration JSON")
	asOf := f.String("as-of", "", "explicit RFC3339 replay clock anchor")
	out := f.String("out", "", "optional new report path")
	if err := f.Parse(args); err != nil {
		return err
	}
	anchor, err := time.Parse(time.RFC3339Nano, *asOf)
	if err != nil || anchor.IsZero() || !*enabled || *state == "" || *trust == "" || *auth == "" || *input == "" || *current == "" || f.NArg() != 0 {
		return errors.New("explicit simulation/state/trust/approval/request/current/as-of required")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); !os.IsNotExist(err) {
			return errors.New("new report path required")
		}
	}
	read := func(path string, limit int64) ([]byte, error) { return bounded(path, limit) }
	raw, err := read(*trust, 16<<10)
	if err != nil {
		return err
	}
	policy, err := actionapproval.DecodeTrust(raw)
	if err != nil {
		return err
	}
	raw, err = read(*auth, 8<<10)
	if err != nil {
		return err
	}
	authorization, err := actionapproval.DecodeSigned(raw)
	if err != nil {
		return err
	}
	raw, err = read(*input, actionproposal.MaxRequest)
	if err != nil {
		return err
	}
	req, err := actionproposal.DecodeRequest(raw)
	if err != nil {
		return err
	}
	raw, err = read(*current, 8<<10)
	if err != nil {
		return err
	}
	latest, err := actionapproval.DecodeCurrentCase(raw)
	if err != nil {
		return err
	}
	source := actionapproval.NewLocalCaseSource()
	if err := source.Put(latest); err != nil {
		return err
	}
	sim, err := actionapproval.NewPolicySimulation()
	if err != nil {
		return err
	}
	l, err := actionapproval.Open(*state, policy, anchor)
	if err != nil {
		return err
	}
	defer l.Close()
	started := time.Now()
	clock := func() time.Time { return anchor.Add(time.Since(started)) }
	receipt, err := l.RunPolicySimulation(req, authorization, source, sim, clock)
	if err != nil {
		return err
	}
	if receipt.Observation == nil || receipt.Observation.State != "active" {
		return errors.New("simulation not confirmed active")
	}
	target := receipt.Entry.Proposal.Target
	r := report{Scope: "private_local_policy_replica", Receipt: receipt, Probes: []probe{}}
	checks := []struct {
		name   string
		target actionproposal.Target
	}{{"approved_target", target}}
	for _, name := range []string{"other_tenant", "other_asset", "other_principal", "other_session", "other_route"} {
		other := target
		switch name {
		case "other_tenant":
			other.Tenant = alternate(other.Tenant)
		case "other_asset":
			other.Asset = alternate(other.Asset)
		case "other_principal":
			other.Principal = alternate(other.Principal)
		case "other_session":
			other.Session = alternate(other.Session)
		case "other_route":
			other.Route = "/api/search"
			if target.Route == other.Route {
				other.Route = "/api/upload"
			}
		}
		checks = append(checks, struct {
			name   string
			target actionproposal.Target
		}{name, other})
	}
	for n, check := range checks {
		denied, err := sim.Probe(check.target, receipt.Observation.Observed)
		if err != nil {
			return err
		}
		if denied != (n == 0) {
			return errors.New("simulation exact-scope probe failed")
		}
		r.Probes = append(r.Probes, probe{check.name, denied})
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		n, err := stdout.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	dest, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := dest.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = dest.Sync()
	}
	closeErr := dest.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "action-simulation refused:", err)
		os.Exit(2)
	}
}
