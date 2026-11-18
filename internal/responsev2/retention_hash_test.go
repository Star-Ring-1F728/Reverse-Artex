//go:build linux || windows

package responsev2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestRetainedStreamingHashMatchesEveryByteAcrossBufferBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, (64 << 10) - 1, 64 << 10, (64 << 10) + 1, 1 << 20} {
		body := make([]byte, size)
		for i := range body {
			body[i] = byte((i*17 + i/(64<<10)) % 251)
		}
		path := filepath.Join(t.TempDir(), "segment.jsonl")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		digest, length, err := hashRetainedFile(path, int64(size))
		if err != nil || length != int64(size) || digest != digestBytes(body) {
			t.Fatalf("size %d: digest=%s length=%d err=%v", size, digest, length, err)
		}
		if size > 0 {
			body[size-1] ^= 0xff
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			changed, n, err := hashRetainedFile(path, int64(size))
			if err != nil || n != int64(size) || changed != digestBytes(body) || changed == digest {
				t.Fatal("final-byte mutation was not bound", size, err)
			}
		}
	}
}

func TestRetainedStreamingHashRejectsNonregularMissingAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "segment")
	if err := os.WriteFile(path, []byte("complete segment"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path  string
		limit int64
	}{{path, 3}, {dir, 1 << 20}, {filepath.Join(dir, "missing"), 1 << 20}} {
		digest, _, err := hashRetainedFile(test.path, test.limit)
		if err == nil || digest != "" {
			t.Fatal("unavailable segment yielded a digest", test.path, err)
		}
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "symlink")
		if err := os.Symlink(path, link); err != nil {
			const privilegeNotHeld = syscall.Errno(1314)
			if runtime.GOOS == "windows" && errors.Is(err, privilegeNotHeld) {
				t.Skip("Windows symlink creation is unavailable to this test account")
			}
			t.Fatal(err)
		}
		if digest, _, err := hashRetainedFile(link, 1<<20); err == nil || digest != "" {
			t.Fatal("symbolic link yielded a digest", err)
		}
	})
}

func TestRetainedRotationFencesUnexpectedPredecessorLength(t *testing.T) {
	for _, change := range []string{"truncate", "grow"} {
		t.Run(change, func(t *testing.T) {
			s, reg, key, _ := retainedFixture(t, DefaultRetentionConfig())
			write := combinedResponseFixture(t, s, reg, key, "length-fence", "own", "allow")
			if err := s.CompleteResponse(write); err != nil {
				t.Fatal(err)
			}
			beforeGeneration, beforeSequence := s.retained.generation, s.sequence
			currentPath := filepath.Join(s.retained.dir, "CURRENT")
			beforePointer, err := os.ReadFile(currentPath)
			if err != nil {
				t.Fatal(err)
			}
			if change == "truncate" {
				err = os.Truncate(s.file.Name(), s.size-1)
			} else {
				_, err = s.file.Write([]byte("\n"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Checkpoint(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unexpected length did not fence rotation", err)
			}
			afterPointer, err := os.ReadFile(currentPath)
			if err != nil {
				t.Fatal(err)
			}
			if !s.failed || s.retained.generation != beforeGeneration || s.sequence != beforeSequence || !bytes.Equal(beforePointer, afterPointer) {
				t.Fatal("length mismatch published a successor checkpoint")
			}
			if err := s.Checkpoint(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("damaged writer resumed", err)
			}
		})
	}
}
