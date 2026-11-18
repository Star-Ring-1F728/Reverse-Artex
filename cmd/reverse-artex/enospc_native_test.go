//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"reverse-artex/internal/recovery"
)

const (
	nativeENOSPCRootEnv = "RA_TEST_ENOSPC_ROOT"
	nativeExt4Magic     = 0xef53
	nativeENOSPCMaxFill = 32 << 20
	nativeHoleBytes     = int64(4 << 20)
)

var nativeENOSPCMountNames = []string{"history-block", "history-inode", "collector-block", "collector-late"}

type nativeENOSPCFSStats struct {
	Path            string `json:"path"`
	TypeMagic       uint64 `json:"type_magic"`
	BlockSize       int64  `json:"block_size"`
	Blocks          uint64 `json:"blocks"`
	BlocksFree      uint64 `json:"blocks_free"`
	BlocksAvailable uint64 `json:"blocks_available"`
	Files           uint64 `json:"files"`
	FilesFree       uint64 `json:"files_free"`
}

type nativeENOSPCFill struct {
	Schema       string              `json:"schema"`
	Test         string              `json:"test"`
	Mount        string              `json:"mount"`
	Filler       string              `json:"filler"`
	Phase        string              `json:"phase"`
	Error        string              `json:"error"`
	Errno        int                 `json:"errno"`
	BytesWritten int64               `json:"bytes_written,omitempty"`
	FilesCreated int                 `json:"files_created,omitempty"`
	Before       nativeENOSPCFSStats `json:"before"`
	After        nativeENOSPCFSStats `json:"after"`
}

func nativeENOSPCLog(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal ENOSPC log: %v", err)
	}
	t.Logf("RA_TEST_ENOSPC %s", raw)
}

func nativeDeviceID(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat device for %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat for %s did not expose Linux device metadata", path)
	}
	return uint64(stat.Dev)
}

func nativeENOSPCStats(t *testing.T, path string) nativeENOSPCFSStats {
	t.Helper()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Fatalf("statfs %s: %v", path, err)
	}
	return nativeENOSPCFSStats{
		Path:            path,
		TypeMagic:       uint64(stat.Type),
		BlockSize:       stat.Bsize,
		Blocks:          stat.Blocks,
		BlocksFree:      stat.Bfree,
		BlocksAvailable: stat.Bavail,
		Files:           stat.Files,
		FilesFree:       stat.Ffree,
	}
}

// nativeENOSPCMount validates all operator-prepared filesystems before a test
// writes anything. The three children must be distinct ext4 mounts, separate
// from both their parent and the host root filesystem.
func nativeENOSPCMount(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv(nativeENOSPCRootEnv)
	if root == "" {
		t.Skipf("set %s to the parent of the three isolated ext4 mounts", nativeENOSPCRootEnv)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("%s must be an absolute path; got %q", nativeENOSPCRootEnv, root)
	}
	root = filepath.Clean(root)
	if root == string(os.PathSeparator) {
		t.Fatal("refusing to use the host root as the ENOSPC test root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve ENOSPC test root %s: %v", root, err)
	}
	if resolvedRoot != root {
		t.Fatalf("ENOSPC test root must not traverse symlinks: %s -> %s", root, resolvedRoot)
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		t.Fatalf("ENOSPC test root directory unavailable: %s (%v)", root, err)
	}
	rootDevice := nativeDeviceID(t, root)
	hostDevice := nativeDeviceID(t, string(os.PathSeparator))

	seen := make(map[uint64]string, len(nativeENOSPCMountNames))
	for _, mountName := range nativeENOSPCMountNames {
		mount := filepath.Join(root, mountName)
		resolvedMount, err := filepath.EvalSymlinks(mount)
		if err != nil {
			t.Fatalf("resolve ENOSPC mount %s: %v", mount, err)
		}
		if resolvedMount != mount || filepath.Dir(resolvedMount) != root {
			t.Fatalf("ENOSPC mount must be a direct, non-symlink child of root: %s -> %s", mount, resolvedMount)
		}
		info, err := os.Stat(mount)
		if err != nil || !info.IsDir() {
			t.Fatalf("ENOSPC mount directory unavailable: %s (%v)", mount, err)
		}
		device := nativeDeviceID(t, mount)
		if device == rootDevice || device == hostDevice {
			t.Fatalf("refusing non-isolated ENOSPC path %s (device=%d root=%d host-root=%d)", mount, device, rootDevice, hostDevice)
		}
		if prior, ok := seen[device]; ok {
			t.Fatalf("ENOSPC mounts must use independent filesystems: %s and %s share device %d", prior, mount, device)
		}
		seen[device] = mount
		stats := nativeENOSPCStats(t, mount)
		if stats.TypeMagic != nativeExt4Magic {
			t.Fatalf("ENOSPC mount is not ext4: %s type=%#x", mount, stats.TypeMagic)
		}
	}
	if !containsString(nativeENOSPCMountNames, name) {
		t.Fatalf("unknown ENOSPC mount name %q", name)
	}
	return filepath.Join(root, name)
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func nativeFixtureOutsideMount(t *testing.T, mount string, f fixture) {
	t.Helper()
	mountDevice := nativeDeviceID(t, mount)
	tempDevice := nativeDeviceID(t, os.TempDir())
	fixtureDevice := nativeDeviceID(t, f.dir)
	if tempDevice == mountDevice || fixtureDevice == mountDevice {
		t.Fatalf("fixture temp data must stay outside the ENOSPC mount: temp=%s fixture=%s mount=%s", os.TempDir(), f.dir, mount)
	}
}

func openNativeContextLive(t *testing.T, f fixture, mount string) (*evidence.Store, *ingester, *contextshadow.Live) {
	t.Helper()
	store, err := evidence.New(f.source, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close context capture store: %v", err)
		}
	})
	engine := detect.New()
	engine.Canaries = map[string]bool{"canary": true}
	host := hostguard.New([]string{"canary"})
	i := &ingester{store: store, engine: engine, hostEngine: host, contextTrust: &f.t}
	historyPath := filepath.Join(mount, "history")
	if _, err := os.Lstat(historyPath); !os.IsNotExist(err) {
		t.Fatalf("refusing reused history path %s: %v", historyPath, err)
	}
	capture := func(ctx context.Context) (*evidence.Snapshot, error) {
		return captureContextSnapshot(ctx, i, f.source)
	}
	live, err := contextshadow.OpenLive(historyPath, f.c, f.a, f.t, capture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(live.Close)
	return store, i, live
}

func fillNativeBlocksToENOSPC(t *testing.T, testName, mount, filler string) nativeENOSPCFill {
	t.Helper()
	before := nativeENOSPCStats(t, mount)
	file, err := os.OpenFile(filler, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	phase := ""
	actual := err
	var written int64
	if err != nil {
		phase = "create"
	} else {
		zero := make([]byte, 64<<10)
		writeSize := int64(len(zero))
		for written < nativeENOSPCMaxFill {
			chunk := writeSize
			if remaining := int64(nativeENOSPCMaxFill) - written; remaining < chunk {
				chunk = remaining
			}
			n, writeErr := file.Write(zero[:int(chunk)])
			written += int64(n)
			if writeErr != nil {
				if errors.Is(writeErr, syscall.ENOSPC) && writeSize > 1024 {
					writeSize = 1024
					continue
				}
				phase, actual = "write", writeErr
				break
			}
			if n != int(chunk) {
				phase, actual = "write", io.ErrShortWrite
				break
			}
			if syncErr := file.Sync(); syncErr != nil {
				phase, actual = "sync", syncErr
				break
			}
		}
		closeErr := file.Close()
		if actual == nil && closeErr != nil {
			phase, actual = "close", closeErr
		}
	}
	after := nativeENOSPCStats(t, mount)
	record := nativeENOSPCFill{
		Schema:       "reverse-artex-native-enospc/1",
		Test:         testName,
		Mount:        mount,
		Filler:       filler,
		Phase:        phase,
		Before:       before,
		After:        after,
		BytesWritten: written,
	}
	if actual != nil {
		record.Error = actual.Error()
		var errno syscall.Errno
		if errors.As(actual, &errno) {
			record.Errno = int(errno)
		}
	}
	nativeENOSPCLog(t, record)
	if phase == "create" || !errors.Is(actual, syscall.ENOSPC) {
		t.Fatalf("expected an actual ENOSPC from block writes or Sync, got phase=%q bytes=%d err=%v", phase, written, actual)
	}
	if written < nativeHoleBytes {
		t.Fatalf("block filler is too short to punch the requested recovery hole: %d < %d", written, nativeHoleBytes)
	}
	return record
}

func fillNativeInodesToENOSPC(t *testing.T, testName, mount, fillerDir string) nativeENOSPCFill {
	t.Helper()
	before := nativeENOSPCStats(t, mount)
	if err := os.Mkdir(fillerDir, 0700); err != nil {
		t.Fatalf("create inode filler directory: %v", err)
	}
	phase := ""
	var actual error
	created := 0
	for n := 0; n < 20000; n++ {
		path := filepath.Join(fillerDir, fmt.Sprintf("empty-%05d", n))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				phase, actual = "create", err
				break
			}
			t.Fatalf("create inode filler %s: %v", path, err)
		}
		created++
		if err := file.Close(); err != nil {
			phase, actual = "close", err
			break
		}
	}
	after := nativeENOSPCStats(t, mount)
	record := nativeENOSPCFill{
		Schema:       "reverse-artex-native-enospc/1",
		Test:         testName,
		Mount:        mount,
		Filler:       fillerDir,
		Phase:        phase,
		Before:       before,
		After:        after,
		FilesCreated: created,
	}
	if actual != nil {
		record.Error = actual.Error()
		var errno syscall.Errno
		if errors.As(actual, &errno) {
			record.Errno = int(errno)
		}
	}
	nativeENOSPCLog(t, record)
	if !errors.Is(actual, syscall.ENOSPC) {
		t.Fatalf("expected actual ENOSPC while creating inode filler files, created=%d err=%v", created, actual)
	}
	if after.FilesFree != 0 || after.BlocksFree == 0 {
		t.Errorf("inode test must exhaust inodes while blocks remain: free_inodes=%d free_blocks=%d", after.FilesFree, after.BlocksFree)
	}
	return record
}

func copyNativeEvidenceFixture(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatalf("create isolated collector source %s: %v", destination, err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("fixture evidence must contain only regular files: %s (%v)", sourcePath, err)
		}
		input, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.OpenFile(filepath.Join(destination, entry.Name()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if err := errors.Join(copyErr, syncErr, closeOutputErr, closeInputErr); err != nil {
			t.Fatalf("copy evidence fixture %s: %v", sourcePath, err)
		}
	}
}

func newNativeCollector(t *testing.T, f fixture, collectorDir string) *ingester {
	t.Helper()
	store, err := evidence.New(collectorDir, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close collector store: %v", err)
		}
	})
	engine := detect.New()
	engine.Canaries = map[string]bool{"canary": true}
	host := hostguard.New([]string{"canary"})
	if err := restoreState(store, collectorDir, "session", []string{"canary"}, engine, host, &f.t); err != nil {
		t.Fatal(err)
	}
	return &ingester{store: store, engine: engine, hostEngine: host, contextTrust: &f.t}
}

func signedNativeBenignBatch(f fixture, count int) []event.Event {
	events := make([]event.Event, count)
	for n := range events {
		e := f.event
		e.EventID = fmt.Sprintf("native-enospc-%03d", n)
		e.RequestID = e.EventID
		e.SessionHMAC = fmt.Sprintf("native-session-%03d", n)
		e.ResourceHMAC = fmt.Sprintf("native-resource-%03d", n)
		e.EventTime = time.Now().UTC()
		e.IngestTime = e.EventTime
		e.Route = "/api/{id}"
		e.Status = http.StatusOK
		e.Authorization = "allow"
		e.Reason = ""
		e.ResourceClass = "normal"
		e.CanaryID = ""
		e.KnownRoute = true
		observation := actioncontext.Observation{Schema: "action-observation/2", Binding: e.ContextBinding(), KeyID: "sensor"}
		observation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(observation)))
		e.Context = &observation
		events[n] = e
	}
	return events
}

func nativeEvidencePrefixHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hashes[entry.Name()] = hex.EncodeToString(sum[:])
	}
	return hashes
}

func postNativeBatch(t *testing.T, handler http.HandlerFunc, events []event.Event, token string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events/group", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func punchNativeBlockHole(t *testing.T, mount, filler string) (nativeENOSPCFSStats, nativeENOSPCFSStats) {
	t.Helper()
	beforeFS := nativeENOSPCStats(t, mount)
	file, err := os.OpenFile(filler, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeFile, err := file.Stat()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if beforeFile.Size() < nativeHoleBytes {
		file.Close()
		t.Fatalf("filler is smaller than hole: %d", beforeFile.Size())
	}
	if err := syscall.Fallocate(int(file.Fd()), uint32(1|2), 0, nativeHoleBytes); err != nil {
		file.Close()
		t.Fatalf("punch 4 MiB hole in filler: %v", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatalf("sync punched filler hole: %v", err)
	}
	afterFile, err := file.Stat()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if afterFile.Size() != beforeFile.Size() {
		file.Close()
		t.Fatalf("hole punching changed filler logical size: before=%d after=%d", beforeFile.Size(), afterFile.Size())
	}
	zeroes := make([]byte, nativeHoleBytes)
	n, err := file.ReadAt(zeroes, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		file.Close()
		t.Fatal(err)
	}
	if n != len(zeroes) {
		file.Close()
		t.Fatalf("read punched filler region: got %d bytes, want %d", n, len(zeroes))
	}
	for _, b := range zeroes {
		if b != 0 {
			file.Close()
			t.Fatal("punching the hole changed filler logical contents")
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	afterFS := nativeENOSPCStats(t, mount)
	if afterFS.BlocksFree <= beforeFS.BlocksFree {
		t.Fatalf("punching filler hole did not return filesystem blocks: before=%d after=%d", beforeFS.BlocksFree, afterFS.BlocksFree)
	}
	return beforeFS, afterFS
}

func TestNativeENOSPCContextShadowBlockFullFailsClosed(t *testing.T) {
	mount := nativeENOSPCMount(t, "history-block")
	t.Setenv("RA_STORAGE_ROOT", "")
	t.Setenv("RA_STORAGE_LIMIT", "")
	f := makeFixture(t)
	nativeFixtureOutsideMount(t, mount, f)
	_, ingest, live := openNativeContextLive(t, f, mount)
	filler := filepath.Join(mount, "block-filler.bin")
	fill := fillNativeBlocksToENOSPC(t, "history-block", mount, filler)

	if err := live.Request(f.c.SHA, false); err != nil {
		t.Fatal(err)
	}
	status := waitContextIdle(t, live, 1)
	nativeENOSPCLog(t, map[string]any{"schema": "reverse-artex-native-enospc/1", "test": "history-block", "phase": "capture-save", "fill": fill, "status": status})
	if status.Storage.State != "failed" {
		t.Errorf("history storage state=%q, want failed", status.Storage.State)
	}
	if status.Enabled {
		t.Error("context shadow remained enabled after physical storage failure")
	}
	if status.Latest != nil {
		t.Errorf("failed attempt became latest: %+v", status.Latest)
	}
	if status.Storage.UnsavedChecks < 1 {
		t.Errorf("unsaved checks=%d, want at least 1", status.Storage.UnsavedChecks)
	}

	live.Close()
	capture := func(ctx context.Context) (*evidence.Snapshot, error) {
		return captureContextSnapshot(ctx, ingest, f.source)
	}
	resumed, resumeErr := contextshadow.OpenLive(filepath.Join(mount, "history"), f.c, f.a, f.t, capture)
	if resumeErr == nil {
		resumed.Close()
		t.Error("context history resumed after ambiguous physical write failure")
	}
	nativeENOSPCLog(t, map[string]any{"schema": "reverse-artex-native-enospc/1", "test": "history-block", "phase": "reopen", "resume_error": errorString(resumeErr)})
}

func TestNativeENOSPCContextShadowInodeFullBlocksResume(t *testing.T) {
	mount := nativeENOSPCMount(t, "history-inode")
	t.Setenv("RA_STORAGE_ROOT", "")
	t.Setenv("RA_STORAGE_LIMIT", "")
	f := makeFixture(t)
	nativeFixtureOutsideMount(t, mount, f)
	_, ingest, live := openNativeContextLive(t, f, mount)
	fill := fillNativeInodesToENOSPC(t, "history-inode", mount, filepath.Join(mount, "fill-inodes"))

	if err := live.Request(f.c.SHA, false); err != nil {
		t.Fatal(err)
	}
	status := waitContextIdle(t, live, 1)
	nativeENOSPCLog(t, map[string]any{"schema": "reverse-artex-native-enospc/1", "test": "history-inode", "phase": "capture-save", "fill": fill, "status": status})
	if status.Storage.State != "failed" {
		t.Errorf("history storage state=%q, want failed", status.Storage.State)
	}
	if status.Enabled {
		t.Error("context shadow remained enabled after inode exhaustion")
	}
	if status.Latest != nil {
		t.Errorf("failed attempt became latest: %+v", status.Latest)
	}

	live.Close()
	capture := func(ctx context.Context) (*evidence.Snapshot, error) {
		return captureContextSnapshot(ctx, ingest, f.source)
	}
	resumed, resumeErr := contextshadow.OpenLive(filepath.Join(mount, "history"), f.c, f.a, f.t, capture)
	if resumeErr == nil {
		resumed.Close()
		t.Error("context history resumed after inode-exhaustion save failure")
	}
	nativeENOSPCLog(t, map[string]any{"schema": "reverse-artex-native-enospc/1", "test": "history-inode", "phase": "reopen", "resume_error": errorString(resumeErr)})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestNativeENOSPCCollectorBlockFullBatchFailsClosed(t *testing.T) {
	mount := nativeENOSPCMount(t, "collector-block")
	t.Setenv("RA_STORAGE_ROOT", "")
	t.Setenv("RA_STORAGE_LIMIT", "")
	t.Setenv("RA_POLICY_CONTROL_URL", "")
	f := makeFixture(t)
	nativeFixtureOutsideMount(t, mount, f)
	collectorDir := filepath.Join(mount, "source")
	copyNativeEvidenceFixture(t, f.source, collectorDir)
	ingest := newNativeCollector(t, f, collectorDir)
	events := signedNativeBenignBatch(f, 64)
	token := strings.Repeat("t", 32)
	handler := appBatchHandlerLimit(ingest, token, "app", "api", map[string]bool{"alpha": true}, make(chan struct{}, 32), 64)
	prefixBefore := nativeEvidencePrefixHashes(t, collectorDir)
	if len(prefixBefore) == 0 {
		t.Fatal("fixture has no committed evidence prefix")
	}
	fill := fillNativeBlocksToENOSPC(t, "collector-block", mount, filepath.Join(mount, "collector-filler.bin"))

	first := postNativeBatch(t, handler, events, token)
	prefixAfterFailure := nativeEvidencePrefixHashes(t, collectorDir)
	if first.Code != http.StatusServiceUnavailable {
		t.Errorf("first full-disk batch status=%d, want 503: %s", first.Code, first.Body.String())
	}
	if first.Header().Get("X-RA-Delivery-Permanent") != "1" || !ingest.degraded() {
		t.Errorf("physical append failure was not latched permanent: header=%q degraded=%v", first.Header().Get("X-RA-Delivery-Permanent"), ingest.degraded())
	}
	if !reflect.DeepEqual(prefixBefore, prefixAfterFailure) {
		t.Errorf("failed append changed the previously acknowledged evidence prefix: before=%v after=%v", prefixBefore, prefixAfterFailure)
	}

	retry := postNativeBatch(t, handler, events, token)
	prefixAfterRetry := nativeEvidencePrefixHashes(t, collectorDir)
	if retry.Code != http.StatusServiceUnavailable {
		t.Errorf("retry while full returned status=%d, want 503", retry.Code)
	}
	if !reflect.DeepEqual(prefixBefore, prefixAfterRetry) {
		t.Errorf("retry changed the previously acknowledged evidence prefix: before=%v after=%v", prefixBefore, prefixAfterRetry)
	}

	punchBefore, punchAfter := punchNativeBlockHole(t, mount, fill.Filler)
	recovered := postNativeBatch(t, handler, events, token)
	prefixAfterRecovery := nativeEvidencePrefixHashes(t, collectorDir)
	if recovered.Code != http.StatusServiceUnavailable {
		t.Errorf("same ingester recovered after space was returned: status=%d, want 503", recovered.Code)
	}
	if !ingest.degraded() {
		t.Error("ingester left degraded state after physical storage recovery")
	}
	if !reflect.DeepEqual(prefixBefore, prefixAfterRecovery) {
		t.Errorf("post-recovery request changed the previously acknowledged evidence prefix: before=%v after=%v", prefixBefore, prefixAfterRecovery)
	}
	nativeENOSPCLog(t, map[string]any{
		"schema":                  "reverse-artex-native-enospc/1",
		"test":                    "collector-block",
		"phase":                   "batch-fail-closed",
		"fill":                    fill,
		"first_status":            first.Code,
		"retry_status":            retry.Code,
		"after_space_returned":    recovered.Code,
		"degraded_after_failure":  ingest.degraded(),
		"prefix_before":           prefixBefore,
		"prefix_after_failure":    prefixAfterFailure,
		"prefix_after_retry":      prefixAfterRetry,
		"prefix_after_recovery":   prefixAfterRecovery,
		"statfs_before_hole":      punchBefore,
		"statfs_after_hole":       punchAfter,
		"filler_logical_contents": "preserved zero bytes; file retained",
	})
}

func TestNativeENOSPCLateEvaluationFailurePreservesUnackedTail(t *testing.T) {
	mount := nativeENOSPCMount(t, "collector-late")
	f := makeFixture(t)
	dir := filepath.Join(mount, "source")
	copyNativeEvidenceFixture(t, f.source, dir)
	i := newNativeCollector(t, f, dir)
	prefix := map[string][]byte{}
	for _, name := range []string{"events", "alerts", "evaluations"} {
		b, e := os.ReadFile(filepath.Join(dir, name+".jsonl"))
		if e != nil {
			t.Fatal(e)
		}
		prefix[name] = b
	}
	// KEEP_SIZE reserves real data blocks only for the events stream. The
	// evaluation stream must allocate new blocks after the disk is filled.
	file, e := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = syscall.Fallocate(int(file.Fd()), 1, 0, 256<<10); e != nil {
		t.Fatal(e)
	}
	file.Sync()
	file.Close()
	fill := fillNativeBlocksToENOSPC(t, "collector-late", mount, filepath.Join(mount, "filler.bin"))
	events := signedNativeBenignBatch(f, 64)
	token := strings.Repeat("t", 32)
	forwarded := 0
	i.forward = func(event.Event) { forwarded++ }
	handler := appBatchHandlerLimit(i, token, "app", "api", map[string]bool{"alpha": true}, make(chan struct{}, 32), 64)
	w := postNativeBatch(t, handler, events, token)
	if w.Code != 503 || !i.degraded() || forwarded != 0 {
		t.Fatal("late failed commit falsely acknowledged", w.Code, i.degraded(), forwarded)
	}
	for name, b := range prefix {
		actual, e := os.ReadFile(filepath.Join(dir, name+".jsonl"))
		if e != nil || len(actual) < len(b) || !bytes.Equal(actual[:len(b)], b) {
			t.Fatal("acknowledged prefix changed", name, e)
		}
	}
	tail, e := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if e != nil || len(tail) <= len(prefix["events"]) {
		t.Fatal("events did not reach durable preallocated stream", e)
	}
	before, after := punchNativeBlockHole(t, mount, fill.Filler)
	if w = postNativeBatch(t, handler, events, token); w.Code != 503 {
		t.Fatal("disk recovery retried uncertain commit", w.Code)
	}
	snapshot, e := evidence.Capture(dir)
	if e != nil {
		t.Fatal(e)
	}
	replay := recovery.VerifySnapshot(snapshot)
	if replay == nil {
		t.Fatal("incomplete evaluation tail replay accepted")
	}
	nativeENOSPCLog(t, map[string]any{"schema": "reverse-artex-native-enospc/1", "test": "collector-late", "phase": "late-commit-refused", "status": w.Code, "forwarded": forwarded, "old_ack_prefix_preserved": true, "unacknowledged_tail_bytes": len(tail) - len(prefix["events"]), "recovery_refused": replay.Error(), "statfs_full": before, "statfs_after_hole": after})
}
