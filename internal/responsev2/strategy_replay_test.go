package responsev2

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestReplayRejectsRehashedCaseTransitionsWithoutChangingSignedProofs(t *testing.T) {
	for _, kind := range []string{"revision", "refs", "tenant", "unrelated_operation", "missing_case", "missing_event", "duplicate_event"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			eligibleFixture(t, s, reg, key)
			s.Close()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var records []record
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
				var r record
				if err := json.Unmarshal(line, &r); err != nil {
					t.Fatal(err)
				}
				records = append(records, r)
			}
			r := &records[len(records)-1]
			switch kind {
			case "revision":
				r.Case.Revision--
			case "refs":
				r.Case.Refs = []string{r.Event.ID}
			case "tenant":
				r.Case.Tenant = "beta"
			case "unrelated_operation":
				r.Operation = "l3-progress"
			case "missing_case":
				r.Case = nil
			case "missing_event":
				r.Event = nil
			case "duplicate_event":
				r.Event = records[0].Event
				r.At = r.Event.At
				c := caseWithEvidence(*records[0].Case, *r.Event)
				r.Case = &c
			}
			if r.Case != nil {
				r.Case.SHA = caseSHA(*r.Case)
			}
			var changed bytes.Buffer
			previous := ""
			for i := range records {
				records[i].Previous = previous
				records[i].SHA = recordSHA(records[i])
				previous = records[i].SHA
				b, _ := json.Marshal(records[i])
				changed.Write(b)
				changed.WriteByte('\n')
			}
			if err := os.WriteFile(path, changed.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, reg)
			if err == nil {
				reopened.Close()
				t.Fatal("rehashed invalid case transition accepted", kind)
			}
		})
	}
}
