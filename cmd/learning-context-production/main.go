package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/contextactivation"
	"reverse-artex/internal/contextrelease"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func writeNew(path string, v any, raw []byte) error {
	if raw == nil {
		var e error
		raw, e = json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		raw = append(raw, '\n')
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	return errors.Join(e, f.Sync(), f.Close())
}
func run(args []string) error {
	f := flag.NewFlagSet("learning-context-production", flag.ContinueOnError)
	action := f.String("action", "status", "policy-template, activate-prepare, rollback-prepare, approve, status, stop, signing-bytes")
	profile := f.String("profile", "", "operator-installed production profile")
	canary := f.String("canary-profile", "", "policy-template original canary profile")
	keys := f.String("approvers", "", "separate public production approver keys")
	release := f.String("release-sha256", "", "completed canary release")
	plan := f.String("plan-sha256", "", "frozen canary evaluation plan")
	source := f.String("evidence", "", "stopped consistent collector evidence")
	memory := f.String("case-memory", "", "current signed-label journal")
	until := f.String("until", "", "fixed RFC3339 production expiry within quality validity")
	nonce := f.String("nonce", "", "new 64-hex nonce; generated if omitted")
	key := f.String("key-id", "", "separate context_production_approver")
	reason := f.String("reason", "", "reviewable reason")
	approval := f.String("approval", "", "signed public production approval")
	journal := f.String("journal", "", "emergency stop journal")
	tenant := f.String("tenant", "", "emergency stop tenant")
	expected := f.Int("expected-revision", -1, "stop CAS")
	out := f.String("out", "", "new output only")
	if e := f.Parse(args); e != nil {
		return e
	}
	allowed := map[string]map[string]bool{
		"policy-template":  {"canary-profile": true, "approvers": true, "out": true},
		"activate-prepare": {"profile": true, "release-sha256": true, "plan-sha256": true, "evidence": true, "case-memory": true, "until": true, "nonce": true, "key-id": true, "reason": true, "out": true},
		"rollback-prepare": {"profile": true, "release-sha256": true, "plan-sha256": true, "evidence": true, "case-memory": true, "until": true, "nonce": true, "key-id": true, "reason": true, "out": true},
		"approve":          {"profile": true, "evidence": true, "case-memory": true, "approval": true, "out": true},
		"status":           {"profile": true, "out": true},
		"stop":             {"journal": true, "tenant": true, "expected-revision": true, "reason": true, "out": true},
		"signing-bytes":    {"approval": true, "out": true},
	}
	fields, ok := allowed[*action]
	bad := !ok || *out == "" || f.NArg() != 0
	f.Visit(func(x *flag.Flag) {
		if x.Name != "action" && !fields[x.Name] {
			bad = true
		}
	})
	if bad {
		return contextactivation.ErrInvalid
	}
	if _, e := os.Lstat(*out); e == nil {
		return os.ErrExist
	} else if !os.IsNotExist(e) {
		return e
	}
	read := contextactivation.ReadPublic
	if *action == "signing-bytes" {
		var a contextactivation.Approval
		if e := read(*approval, &a); e != nil {
			return e
		}
		return writeNew(*out, nil, contextactivation.SigningBytes(a))
	}
	if *action == "policy-template" {
		c, _, e := contextrelease.LoadProfile(*canary)
		if e != nil {
			return e
		}
		var k struct {
			Approvers []contextrelease.Approver `json:"approvers"`
		}
		if e = read(*keys, &k); e != nil {
			return e
		}
		p := contextactivation.DefaultPolicy(c.Policy.Tenant, k.Approvers)
		if e = contextactivation.ValidatePolicy(p, c); e != nil {
			return e
		}
		return writeNew(*out, p, nil)
	}
	if *action == "stop" {
		s, e := contextactivation.Open(*journal)
		if e != nil {
			return e
		}
		defer s.Close()
		v, e := s.Stop(*tenant, *expected, *reason, time.Now().UTC())
		if e != nil {
			return e
		}
		return writeNew(*out, v, nil)
	}
	p, _, path, canaryPath, e := contextactivation.LoadProfile(*profile)
	if e != nil {
		return e
	}
	s, e := contextactivation.Open(path)
	if e != nil {
		return e
	}
	defer s.Close()
	if *action == "status" {
		return writeNew(*out, s.View(), nil)
	}
	var a contextactivation.Approval
	if *action == "approve" {
		if e = read(*approval, &a); e != nil {
			return e
		}
		*release, *plan = a.Request.ReleaseSHA, a.Request.PlanSHA
	}
	check, e := contextactivation.OpenCheck(canaryPath, *release, *plan, *source, *memory, time.Now().UTC())
	if e != nil {
		return e
	}
	defer check.Close()
	if *action == "approve" {
		v, e := s.ApproveCurrent(check, a, time.Now().UTC(), func() (contextactivation.Policy, error) {
			current, _, currentPath, currentCanary, err := contextactivation.LoadProfile(*profile)
			if err != nil {
				return current, err
			}
			if currentPath != path || currentCanary != canaryPath {
				return current, contextactivation.ErrConflict
			}
			return current, nil
		})
		if e != nil {
			return e
		}
		return writeNew(*out, v, nil)
	}
	u, e := time.Parse(time.RFC3339Nano, *until)
	if e != nil {
		return e
	}
	if *nonce == "" {
		var raw [32]byte
		if _, e = rand.Read(raw[:]); e != nil {
			return e
		}
		*nonce = hex.EncodeToString(raw[:])
	}
	kind := "activate"
	if *action == "rollback-prepare" {
		kind = "rollback"
	}
	now := time.Now().UTC()
	request, e := s.Prepare(p, check, kind, u, *nonce, *reason, now)
	if e != nil {
		return e
	}
	a = contextactivation.Approval{Schema: "case-context-production-approval/2", Tenant: p.Tenant, Request: request, KeyID: *key, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	return writeNew(*out, a, nil)
}
