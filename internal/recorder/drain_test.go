package recorder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

func newTestManager(t *testing.T) (*Manager, store.Paths) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	manager, err := NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths
}

func bufferFrames(t *testing.T, manager *Manager, segmentID string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		frame := Frame{Sequence: uint64(i + 1), Epoch: 1, Payload: []byte("frame-payload-")}
		if err := manager.Buffer(segmentID, frame); err != nil {
			t.Fatalf("buffer frame %d: %v", i+1, err)
		}
	}
}

// countingContext allows the first permits calls to Err() to succeed and then
// reports canceled, pinning the drain to an exact frame boundary.
type countingContext struct {
	permits int
}

func (c *countingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *countingContext) Done() <-chan struct{}       { return nil }
func (c *countingContext) Value(any) any               { return nil }

func (c *countingContext) Err() error {
	if c.permits > 0 {
		c.permits--
		return nil
	}
	return context.Canceled
}

func TestDrainCancelPreservesBoundaryAndRetryWritesNoDuplicates(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("PASS-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrames(t, manager, segment.ID, 5)

	partial, err := manager.Drain(&countingContext{permits: 3}, segment.ID)
	if err == nil {
		t.Fatal("canceled drain unexpectedly succeeded")
	}
	if !partial.Canceled {
		t.Fatalf("expected canceled result, got %#v", partial)
	}
	if partial.WrittenThisRun != 3 || partial.FramesWritten != 3 || partial.Remaining != 2 {
		t.Fatalf("boundary after cancel wrong: %#v", partial)
	}

	report, err := manager.writer.Verify(segment.ID)
	if err != nil || !report.Healthy() || report.FramesOnDisk != 3 {
		t.Fatalf("file after cancel should hold exactly 3 intact frames: %#v %v", report, err)
	}
	if got := manager.List()[0]; got.FramesWritten != 3 || got.FramesBuffered != 2 {
		t.Fatalf("counters after cancel wrong: %#v", got)
	}

	rest, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatalf("retry drain failed: %v", err)
	}
	if rest.WrittenThisRun != 2 || rest.FramesWritten != 5 || rest.Remaining != 0 || !rest.Complete {
		t.Fatalf("retry drain result wrong: %#v", rest)
	}

	report, err = manager.writer.Verify(segment.ID)
	if err != nil || report.FramesOnDisk != 5 {
		t.Fatalf("retry duplicated frames: %#v %v", report, err)
	}
	expectedChecksum := fileSHA256(t, paths.Recording(segment.ID))
	if rest.ChecksumSHA256 != expectedChecksum {
		t.Fatalf("drain checksum %s != file hash %s", rest.ChecksumSHA256, expectedChecksum)
	}

	sealed, err := manager.Seal(segment.ID, "test complete")
	if err != nil || !sealed.Complete {
		t.Fatalf("seal failed: %#v %v", sealed, err)
	}
	if sealed.Segment.ChecksumSHA256 != expectedChecksum {
		t.Fatalf("seal checksum %s != file hash %s", sealed.Segment.ChecksumSHA256, expectedChecksum)
	}

	// Sealing is idempotent and keeps the same attestation.
	again, err := manager.Seal(segment.ID, "test complete")
	if err != nil || !again.Complete || again.Segment.ChecksumSHA256 != expectedChecksum {
		t.Fatalf("repeat seal changed state: %#v %v", again, err)
	}
}

func TestDrainTrimsTornTailBeforeResuming(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("PASS-2", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrames(t, manager, segment.ID, 5)

	// Three frames land, then a torn partial record from an interrupted write.
	if _, err := manager.Drain(&countingContext{permits: 3}, segment.ID); err == nil {
		t.Fatal("expected canceled drain")
	}
	path := manager.path2Recording(segment.ID)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := manager.writer.Verify(segment.ID)
	if err != nil || report.TailBytes != 6 || report.FramesOnDisk != 3 {
		t.Fatalf("torn tail not detected: %#v %v", report, err)
	}

	rest, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatalf("drain over torn tail failed: %v", err)
	}
	if rest.WrittenThisRun != 2 || rest.FramesWritten != 5 || !rest.Complete {
		t.Fatalf("drain over torn tail wrong: %#v", rest)
	}
	report, _ = manager.writer.Verify(segment.ID)
	if !report.Healthy() || report.FramesOnDisk != 5 {
		t.Fatalf("recording should hold 5 intact frames: %#v", report)
	}
}

func TestSealRequiresEmptyBufferAndHealthyFile(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("PASS-3", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrames(t, manager, segment.ID, 2)

	preview, err := manager.PreviewSeal(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Ready || len(preview.Blockers) == 0 {
		t.Fatalf("buffered segment should not be seal-ready: %#v", preview)
	}
	if !preview.Verified {
		t.Fatalf("empty file should verify as healthy: %#v", preview)
	}
	if result, err := manager.Seal(segment.ID, "early"); err == nil || result.Complete {
		t.Fatalf("seal with buffered frames should fail: %#v %v", result, err)
	}

	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}

	// Corrupt the file after a clean drain: seal must refuse without trimming.
	path := manager.path2Recording(segment.ID)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("garbage-tail"))
	_ = file.Close()

	preview, err = manager.PreviewSeal(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Ready || preview.Verified {
		t.Fatalf("corrupt segment should not be seal-ready: %#v", preview)
	}
	result, err := manager.Seal(segment.ID, "over corrupt tail")
	if err == nil || result.Complete {
		t.Fatalf("seal over corrupt tail should fail: %#v %v", result, err)
	}
	if info, _ := os.Stat(path); info.Size() == 0 {
		t.Fatal("seal must not repair or truncate the file")
	}

	// A drain with an empty buffer repairs the tail, after which seal works.
	repaired, err := manager.Drain(context.Background(), segment.ID)
	if err != nil || !repaired.Complete {
		t.Fatalf("repair drain failed: %#v %v", repaired, err)
	}
	if _, err := manager.Seal(segment.ID, "after repair"); err != nil {
		t.Fatalf("seal after repair failed: %v", err)
	}
}

func TestPreviewOnSealedSegmentReattestsChecksum(t *testing.T) {
	manager, paths := newTestManager(t)
	segment, err := manager.Start("PASS-4", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrames(t, manager, segment.ID, 1)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Seal(segment.ID, "done"); err != nil {
		t.Fatal(err)
	}

	preview, err := manager.PreviewSeal(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Ready || preview.Status != Sealed {
		t.Fatalf("sealed segment preview must not be re-sealable: %#v", preview)
	}
	if !preview.Verified || preview.ChecksumSHA256 != fileSHA256(t, paths.Recording(segment.ID)) {
		t.Fatalf("sealed preview checksum wrong: %#v", preview)
	}

	// Tamper with the sealed file: verification must flag the mismatch.
	file, err := os.OpenFile(paths.Recording(segment.ID), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte{0xff})
	_ = file.Close()
	preview, err = manager.PreviewSeal(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Verified {
		t.Fatalf("tampered sealed file must fail verification: %#v", preview)
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// path2Recording exposes the on-disk recording path for tests.
func (m *Manager) path2Recording(segmentID string) string {
	return m.writer.paths.Recording(segmentID)
}

func TestConcurrentDrainsWriteNoDuplicates(t *testing.T) {
	manager, _ := newTestManager(t)
	segment, err := manager.Start("PASS-5", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	bufferFrames(t, manager, segment.ID, 20)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = manager.Drain(context.Background(), segment.ID)
		}()
	}
	wg.Wait()

	report, err := manager.writer.Verify(segment.ID)
	if err != nil || !report.Healthy() {
		t.Fatalf("file unhealthy after concurrent drains: %#v %v", report, err)
	}
	if report.FramesOnDisk != 20 {
		t.Fatalf("expected 20 frames after concurrent drains, got %d", report.FramesOnDisk)
	}
	if got := manager.List()[0]; got.FramesWritten != 20 || got.FramesBuffered != 0 {
		t.Fatalf("counters wrong after concurrent drains: %#v", got)
	}
}
