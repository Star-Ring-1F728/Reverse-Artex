// decisions-check performs one explicit synthetic real Decisions call.
// The secret is read only by the runtime and is never printed or written.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	api "reverse-artex/internal/decisions/openai"
	"strings"
	"time"
)

func run(args []string, stdout io.Writer) error {
	f := flag.NewFlagSet("decisions-check", flag.ContinueOnError)
	keyFile := f.String("key-file", "", "explicit Windows current-user DPAPI credential file")
	live := f.Bool("live", false, "explicitly permit one real synthetic API request")
	keyEnv := f.String("key-env", "OPENAI_API_KEY", "server environment variable name")
	out := f.String("out", "", "new result file; no credentials or raw inputs are saved")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !*live || *out == "" || f.NArg() != 0 {
		return fmt.Errorf("explicit -live and new -out path required")
	}
	cfg := api.Config{Revision: "smoke-v1", Mode: "shadow", KeyEnv: *keyEnv, DailyCalls: 1, DailyTokens: 8192, ReserveTokens: 8192}
	if *keyFile != "" {
		cfg.KeyFile = *keyFile
		cfg.KeyEnv = ""
	}
	if cfg.Validate() != nil {
		return api.ErrConfig
	}
	if _, err := os.Lstat(*out); !os.IsNotExist(err) {
		return fmt.Errorf("new result path required")
	}
	file, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.WriteString("{\"status\":\"reserved_unknown_if_interrupted\"}\n"); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	now := time.Now()
	input := api.Input{Schema: "decision-input/2", CaseID: "c2-" + strings.Repeat("a", 32), CaseSHA: strings.Repeat("b", 64), Revision: 1, Epoch: 1, Tenant: strings.Repeat("c", 64), Asset: strings.Repeat("d", 64), Facts: []api.Fact{{EvidenceID: strings.Repeat("e", 64), Kind: "authorized_representation", Route: strings.Repeat("f", 64), Resource: strings.Repeat("a", 64), AgeMS: 0}}, Candidates: []string{}, Coverage: "registered_sdk_edge_only", PendingReview: true, Enqueued: now.UTC(), Expires: now.Add(5 * time.Second).UTC(), QuestionSHA: api.QuestionSHA()}
	client := api.New(func() string { return api.ResolveKey(cfg) })
	defer client.Close()
	result := client.Decide(context.Background(), input)
	record := map[string]any{"schema": "decisions-live-smoke/1", "purpose": "one synthetic, non-policy connectivity check", "result": result, "policy_mutations": 0}
	if err = file.Truncate(0); err != nil {
		return err
	}
	if _, err = file.Seek(0, 0); err != nil {
		return err
	}
	if err = json.NewEncoder(file).Encode(record); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Console output deliberately contains only nonsecret status/provenance.
	fmt.Fprintf(stdout, "Decisions status=%s model=%s HTTP=%d; result saved\n", result.Status, result.Model, result.HTTPStatus)
	if result.Status != "ok" {
		return fmt.Errorf("real Decisions smoke did not complete successfully; inspect typed saved status")
	}
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "decisions-check:", err)
		os.Exit(2)
	}
}
