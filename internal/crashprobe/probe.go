//go:build ntfscrashprobe

// Package crashprobe is linked only by explicit test-overlay builds.
package crashprobe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var once sync.Once

func Armed(point string) bool {
	if os.Getenv("RA_CRASH_POINT") != point {
		return false
	}
	dir := os.Getenv("RA_CRASH_CONTROL")
	if !filepath.IsAbs(dir) {
		return false
	}
	info, err := os.Stat(filepath.Join(dir, "armed.json"))
	return err == nil && info.Mode().IsRegular()
}
func Pause(point string) {
	if !Armed(point) {
		return
	}
	once.Do(func() {
		dir := os.Getenv("RA_CRASH_CONTROL")
		b, _ := json.Marshal(map[string]any{"schema": "ntfs-crash-barrier/1", "point": point, "pid": os.Getpid(), "at": time.Now().UTC()})
		f, err := os.OpenFile(filepath.Join(dir, "reached.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		if _, err = f.Write(b); err != nil {
			panic(err)
		}
		if err = f.Sync(); err != nil {
			panic(err)
		}
		if err = f.Close(); err != nil {
			panic(err)
		}
		for {
			time.Sleep(time.Second)
		}
	})
}

// AwaitWorker lets the HTTP test path observe a worker already paused while it
// owns Live.mu. This makes the admission-response regression deterministic.
func AwaitWorker() {
	point := os.Getenv("RA_CRASH_POINT")
	if len(point) < 8 || (point[:8] != "observer" && point[:8] != "rotation") || !Armed(point) {
		return
	}
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if _, err := os.Stat(filepath.Join(os.Getenv("RA_CRASH_CONTROL"), "reached.json")); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	panic("worker barrier not reached before admission response")
}
