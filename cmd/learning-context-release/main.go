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
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func writeNew(path string, value any, raw []byte) error {
	if raw == nil {
		var e error
		raw, e = json.MarshalIndent(value, "", "  ")
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
	flags := flag.NewFlagSet("learning-context-release", flag.ContinueOnError)
	action := flags.String("action", "status", "status, canary-prepare, rollback-prepare, approve, stop, package, signing-bytes, policy-template")
	profile := flags.String("profile", "", "operator-installed profile paths")
	journal := flags.String("journal", "", "offline journal for emergency stop/package export")
	bundlePath := flags.String("bundle", "", "public quality capsule and endorsement bundle")
	bundlePin := flags.String("bundle-sha256", "", "approved package to export")
	approvalPath := flags.String("approval", "", "signed public canary approval")
	source := flags.String("evidence", "", "stopped collector evidence")
	tenant := flags.String("tenant", "", "emergency stop tenant")
	expected := flags.Int("expected-revision", -1, "emergency stop CAS")
	reason := flags.String("reason", "", "reviewable reason")
	percent := flags.Int("percent", 0, "candidate advisory branch, 1-50 percent")
	until := flags.String("until", "", "fixed RFC3339 canary lease")
	nonce := flags.String("nonce", "", "fresh 64-hex nonce; generated if omitted")
	key := flags.String("key-id", "", "separate context_canary_approver")
	admissionPath := flags.String("admission-policy", "", "policy-template input")
	authorityPath := flags.String("authority-trust", "", "policy-template public authority keys")
	contextPath := flags.String("context-trust", "", "policy-template public sensor/issuer keys")
	approversPath := flags.String("approvers", "", "policy-template public approver list")
	out := flags.String("out", "", "new output, never overwrites")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *out == "" {
		return contextrelease.ErrInvalid
	}
	allowed := map[string]map[string]bool{
		"status":           {"profile": true, "out": true},
		"canary-prepare":   {"profile": true, "bundle": true, "evidence": true, "percent": true, "until": true, "nonce": true, "key-id": true, "reason": true, "out": true},
		"rollback-prepare": {"profile": true, "bundle": true, "evidence": true, "percent": true, "until": true, "nonce": true, "key-id": true, "reason": true, "out": true},
		"approve":          {"profile": true, "bundle": true, "evidence": true, "approval": true, "out": true},
		"stop":             {"journal": true, "tenant": true, "expected-revision": true, "reason": true, "out": true},
		"package":          {"journal": true, "bundle-sha256": true, "out": true},
		"signing-bytes":    {"approval": true, "out": true},
		"policy-template":  {"admission-policy": true, "authority-trust": true, "context-trust": true, "approvers": true, "out": true},
	}
	fields, ok := allowed[*action]
	if !ok {
		return contextrelease.ErrInvalid
	}
	bad := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name != "action" && !fields[f.Name] {
			bad = true
		}
	})
	if bad {
		return contextrelease.ErrInvalid
	}
	if _, e := os.Lstat(*out); e == nil {
		return os.ErrExist
	} else if !os.IsNotExist(e) {
		return e
	}
	read := contextshadow.ReadPublic
	if *action == "signing-bytes" {
		var a contextrelease.Approval
		if e := read(*approvalPath, &a); e != nil {
			return e
		}
		return writeNew(*out, nil, contextrelease.SigningBytes(a))
	}
	if *action == "policy-template" {
		var p contextadmission.Policy
		var a casememory.LearningTrust
		var ctx actioncontext.Trust
		var keys struct {
			Approvers []contextrelease.Approver `json:"approvers"`
		}
		for _, input := range []struct {
			path  string
			value any
		}{{*admissionPath, &p}, {*authorityPath, &a}, {*contextPath, &ctx}, {*approversPath, &keys}} {
			if e := read(input.path, input.value); e != nil {
				return e
			}
		}
		r := contextrelease.DefaultPolicy(p.Tenant, contextlearning.Digest(p), keys.Approvers)
		if e := contextrelease.ValidateConfig(contextrelease.Config{Policy: r, Admission: p, Authorities: a, Context: ctx}); e != nil {
			return e
		}
		return writeNew(*out, r, nil)
	}
	var cfg contextrelease.Config
	path := *journal
	if *profile != "" {
		var e error
		cfg, path, e = contextrelease.LoadProfile(*profile)
		if e != nil {
			return e
		}
	}
	if path == "" {
		return contextrelease.ErrInvalid
	}
	if *action == "canary-prepare" || *action == "rollback-prepare" {
		known := false
		for _, approver := range cfg.Policy.Approvers {
			known = known || approver.ID == *key && !approver.Revoked
		}
		if !known {
			return contextrelease.ErrInvalid
		}
	}
	store, e := contextrelease.Open(path)
	if e != nil {
		return e
	}
	defer store.Close()
	var result any
	switch *action {
	case "status":
		result = store.View(cfg, time.Now().UTC())
	case "stop":
		v, e := store.Stop(*tenant, *expected, *reason, time.Now().UTC())
		if e != nil {
			return e
		}
		result = v
	case "package":
		b, e := store.Package(*bundlePin)
		if e != nil {
			return e
		}
		result = b
	default:
		var b contextrelease.Bundle
		if e := read(*bundlePath, &b); e != nil {
			return e
		}
		snapshot, e := evidence.Capture(*source)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		if *action == "approve" {
			var a contextrelease.Approval
			if e = read(*approvalPath, &a); e != nil {
				return e
			}
			v, e := store.Approve(cfg, b, snapshot, a, now)
			if e != nil {
				return e
			}
			result = map[string]any{"change": v, "status": store.View(cfg, now)}
		} else {
			end, e := time.Parse(time.RFC3339Nano, *until)
			if e != nil {
				return e
			}
			n := *nonce
			if n == "" {
				raw := make([]byte, 32)
				if _, e = rand.Read(raw); e != nil {
					return e
				}
				n = hex.EncodeToString(raw)
			}
			kind := "canary"
			if *action == "rollback-prepare" {
				kind = "rollback"
			}
			r, e := store.Prepare(cfg, b, snapshot, kind, *percent, end, n, *reason, now)
			if e != nil {
				return e
			}
			result = contextrelease.Approval{Schema: "case-context-canary-approval/2", Tenant: cfg.Policy.Tenant, Request: r, KeyID: *key, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
		}
	}
	return writeNew(*out, result, nil)
}
