package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"reverse-artex/internal/control"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9084", "private control listener")
	out := flag.String("out", "artifacts/control", "durable policy audit")
	flag.Parse()
	names := []string{"RA_POLICY_ADMIN_TOKEN", "RA_POLICY_READER_TOKEN", "RA_POLICY_EVIDENCE_TOKEN", "RA_POLICY_SNAPSHOT_KEY"}
	keys := map[string]string{}
	seen := map[string]bool{}
	for _, n := range names {
		v := os.Getenv(n)
		if len(v) < 32 || seen[v] {
			log.Fatal("distinct control credentials required")
		}
		keys[n] = v
		seen[v] = true
	}
	m, err := control.OpenPersistent(*out)
	if err != nil {
		log.Fatal("policy audit unavailable")
	}
	defer m.Close()
	h := control.Handler(m, control.Tokens{Admin: keys[names[0]], Reader: keys[names[1]], Evidence: keys[names[2]], SnapshotKey: []byte(keys[names[3]])})
	s := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	log.Fatal(s.ListenAndServe())
}
