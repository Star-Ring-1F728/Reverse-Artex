// defense-mode is a local, fake-only shadow lab. It never loads an external
// provider or connects to collector/control, and cannot apply policies.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/assistance"
	"time"
)

type submission struct {
	ID       string `json:"id,omitempty"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}
type report struct {
	Scope             string          `json:"scope"`
	LongTest          bool            `json:"long_test"`
	DiskInvestigation bool            `json:"disk_investigation"`
	View              assistance.View `json:"view"`
	Submissions       []submission    `json:"submissions"`
}

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("bounded regular input file required")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("input too large")
	}
	return data, err
}
func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("defense-mode", flag.ContinueOnError)
	f.SetOutput(stderr)
	state := f.String("state", "", "explicit owned local state file")
	action := f.String("action", "status", "configure | status | run")
	config := f.String("config", "", "strict JSON configuration for configure")
	input := f.String("input", "", "bounded metadata snapshot JSONL for run")
	actor := f.String("operator", "local-operator", "local OS-operator audit label; not an authentication credential")
	out := f.String("out", "", "optional new report path; never overwrites")
	waitMS := f.Int("wait-ms", 65000, "bounded wait, 1..65000 milliseconds")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *state == "" || *waitMS < 1 || *waitMS > 65000 || (*action != "status" && *action != "configure" && *action != "run") {
		return errors.New("invalid action, state or wait")
	}
	if (*action == "configure") != (*config != "") || (*action == "run") != (*input != "") {
		return errors.New("config only for configure; input only for run")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); !os.IsNotExist(err) {
			return errors.New("new report path required")
		}
	}
	var cfg assistance.Config
	if *action == "configure" {
		data, err := boundedFile(*config, 4096)
		if err != nil {
			return err
		}
		cfg, err = assistance.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return err
		}
	}
	snapshots := []assistance.Snapshot{}
	if *action == "run" {
		data, err := boundedFile(*input, assistance.MaxQueue*assistance.MaxSnapshot)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, assistance.MaxSnapshot+1), assistance.MaxSnapshot+1)
		for scanner.Scan() {
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			s, err := assistance.DecodeSnapshot(scanner.Bytes())
			if err != nil {
				return err
			}
			snapshots = append(snapshots, s)
			if len(snapshots) > assistance.MaxQueue {
				return errors.New("at most 100 snapshots per invocation")
			}
		}
		if err = scanner.Err(); err != nil {
			return err
		}
		if len(snapshots) == 0 {
			return errors.New("nonempty snapshots required")
		}
	}
	c, err := assistance.Open(*state)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	}()
	if *action == "configure" {
		if _, err = c.Apply(cfg, *actor); err != nil {
			return err
		}
	}
	r := report{Scope: "fake-only local shadow contracts; base services not connected", Submissions: []submission{}}
	for _, s := range snapshots {
		j, err := c.Submit(s)
		if err != nil {
			label := "unavailable"
			if errors.Is(err, assistance.ErrCapacity) {
				label = "capacity"
			}
			r.Submissions = append(r.Submissions, submission{Accepted: false, Error: label})
		} else {
			r.Submissions = append(r.Submissions, submission{ID: j.ID, Accepted: true})
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*waitMS)*time.Millisecond)
	defer cancel()
	if err = c.Wait(ctx); err != nil {
		return err
	}
	r.View = c.Inspect()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = stdout.Write(data)
		return err
	}
	handle, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer handle.Close()
	n, err := handle.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = handle.Sync()
	}
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "defense-mode refused:", err)
		os.Exit(2)
	}
}
