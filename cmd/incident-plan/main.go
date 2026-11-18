// incident-plan creates a read-only case projection for review before any DB write.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
)

func main() {
	source := flag.String("evidence", "", "existing M6-2 evidence directory")
	output := flag.String("out", "", "new projection manifest path")
	flag.Parse()
	if *source == "" || *output == "" {
		log.Fatal("-evidence and -out are required")
	}
	info, err := os.Stat(*source)
	if err != nil || !info.IsDir() {
		log.Fatal("existing evidence directory required")
	}
	store, err := evidence.New(*source, 64<<20)
	if err != nil {
		log.Fatal(err)
	}
	manifest, err := incident.Build(store)
	if err != nil {
		log.Fatal(err)
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		file.Close()
		log.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		log.Fatal(err)
	}
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
}
