// Local runtime-budget interoperability/crash probe. No network or policy API.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reverse-artex/internal/storagebudget"
	"time"
)

func main() {
	path := flag.String("path", "", "new fixture file inside shared root")
	size := flag.Int("bytes", 256, "bounded fixture bytes")
	hold := flag.Int("hold-ms", 0, "hold lock before write, max 5000ms")
	flag.Parse()
	if *path == "" || *size < 1 || *size > 1<<20 || *hold < 0 || *hold > 5000 {
		os.Exit(2)
	}
	b, e := storagebudget.FromEnv(*path)
	if e != nil || b == nil {
		fmt.Println(`{"passed":false}`)
		os.Exit(2)
	}
	e = b.With(func(l *storagebudget.Lease) error {
		if e := l.Allow(int64(*size)); e != nil {
			return e
		}
		fmt.Println(`{"locked":true}`)
		time.Sleep(time.Duration(*hold) * time.Millisecond)
		f, e := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		data := make([]byte, *size)
		n, e := f.Write(data)
		if e == nil && n != len(data) {
			e = fmt.Errorf("short probe write")
		}
		if e == nil {
			e = f.Sync()
		}
		return e
	})
	if e != nil {
		fmt.Println(`{"passed":false}`)
		os.Exit(1)
	}
	value, e := b.Stats()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": e == nil, "status": value})
}
