package recorder

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

func newTestManager(t *testing.T) (*Manager, store.Paths) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	manager, err := NewManager(paths, audit.NewTrail(store.NewAppendLog(paths)))
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths
}

func startSegment(t *testing.T, manager *Manager, frames, payloadSize int) Segment {
	t.Helper()
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < frames; i++ {
		payload := []byte(fmt.Sprintf("frame-%06d|", i))
		for len(payload) < payloadSize {
			payload = append(payload, byte(i%251))
		}
		if err := manager.Buffer(segment.ID, Frame{Sequence: uint64(i), Epoch: 1, Payload: payload[:payloadSize]}); err != nil {
			t.Fatal(err)
		}
	}
	return segment
}

func readRecording(t *testing.T, paths store.Paths, segmentID string) []Frame {
	t.Helper()
	data, err := os.ReadFile(paths.Recording(segmentID))
	if err != nil {
		t.Fatal(err)
	}
	var frames []Frame
	for len(data) > 0 {
		if len(data) < frameHeaderSize {
			t.Fatalf("recording has %d trailing bytes", len(data))
		}
		length := binary.BigEndian.Uint64(data[16:24])
		if uint64(len(data)) < uint64(frameHeaderSize)+length {
			t.Fatal("recording has a truncated payload")
		}
		frames = append(frames, Frame{
			Sequence: binary.BigEndian.Uint64(data[0:8]),
			Epoch:    int64(binary.BigEndian.Uint64(data[8:16])),
			Payload:  append([]byte(nil), data[frameHeaderSize:frameHeaderSize+int(length)]...),
			CRC32:    binary.BigEndian.Uint32(data[24:28]),
		})
		data = data[frameHeaderSize+int(length):]
	}
	return frames
}

func requireUniqueSequences(t *testing.T, frames []Frame, want int) {
	t.Helper()
	if len(frames) != want {
		t.Fatalf("recording holds %d frames, want %d", len(frames), want)
	}
	seen := make(map[uint64]int, want)
	for _, frame := range frames {
		seen[frame.Sequence]++
	}
	for i := 0; i < want; i++ {
		if seen[uint64(i)] != 1 {
			t.Fatalf("sequence %d appears %d times in recording", i, seen[uint64(i)])
		}
	}
}

func TestDrainCanceledBeforeStartKeepsBoundary(t *testing.T) {
	manager, paths := newTestManager(t)
	const total = 10
	segment := startSegment(t, manager, total, 64)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := manager.Drain(ctx, segment.ID)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !outcome.Canceled || outcome.Drained != 0 {
		t.Fatalf("unexpected canceled outcome: %+v", outcome)
	}
	progress, err := manager.DrainProgress(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.FramesWritten != 0 || progress.FramesBuffered != total {
		t.Fatalf("boundary moved on cancel: %+v", progress)
	}
	if !progress.Verified {
		t.Fatalf("empty recording failed verification: %s", progress.VerifyError)
	}

	retry, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Drained != total {
		t.Fatalf("retry wrote %d frames, want %d", retry.Drained, total)
	}
	requireUniqueSequences(t, readRecording(t, paths, segment.ID), total)

	// Draining an empty buffer is a no-op and must not duplicate frames.
	again, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Drained != 0 {
		t.Fatalf("empty drain wrote %d frames", again.Drained)
	}
	requireUniqueSequences(t, readRecording(t, paths, segment.ID), total)
}

func TestDrainCancelMidwayPreservesBoundaryAndRetrySkipsWritten(t *testing.T) {
	manager, paths := newTestManager(t)
	const total = 600
	segment := startSegment(t, manager, total, 256)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if size, _ := manager.writer.Size(segment.ID); size >= 3*(frameHeaderSize+256) {
					cancel()
					return
				}
			}
		}
	}()
	outcome, err := manager.Drain(ctx, segment.ID)
	close(done)
	if err == nil {
		// The drain outran the canceler; the boundary invariants must still hold.
		if outcome.Drained != total {
			t.Fatalf("successful drain wrote %d of %d frames", outcome.Drained, total)
		}
	} else if !outcome.Canceled {
		t.Fatalf("drain failed without cancellation: %v", err)
	}
	if outcome.Progress.FramesWritten != outcome.Drained {
		t.Fatalf("progress shows %d written, drain reported %d", outcome.Progress.FramesWritten, outcome.Drained)
	}
	if outcome.Progress.FramesBuffered != total-outcome.Drained {
		t.Fatalf("progress shows %d buffered, want %d", outcome.Progress.FramesBuffered, total-outcome.Drained)
	}
	if !outcome.Progress.Verified {
		t.Fatalf("partial recording failed verification: %s", outcome.Progress.VerifyError)
	}

	// The retry resumes at the committed boundary and writes only the rest.
	retry, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Drained != total-outcome.Drained {
		t.Fatalf("retry wrote %d frames, want %d", retry.Drained, total-outcome.Drained)
	}
	requireUniqueSequences(t, readRecording(t, paths, segment.ID), total)

	progress, err := manager.DrainProgress(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.FramesWritten != total || progress.FramesBuffered != 0 || !progress.SealReady {
		t.Fatalf("unexpected progress after retry: %+v", progress)
	}
}

func TestDrainRejectsConcurrentDrain(t *testing.T) {
	manager, paths := newTestManager(t)
	const total = 800
	segment := startSegment(t, manager, total, 512)

	first := make(chan error, 1)
	go func() {
		outcome, err := manager.Drain(context.Background(), segment.ID)
		if err == nil && outcome.Drained != total {
			err = fmt.Errorf("first drain wrote %d of %d frames", outcome.Drained, total)
		}
		first <- err
	}()
	_, secondErr := manager.Drain(context.Background(), segment.ID)
	firstErr := <-first

	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("exactly one drain should win: first=%v second=%v", firstErr, secondErr)
	}
	for _, err := range []error{firstErr, secondErr} {
		if err != nil && !strings.Contains(err.Error(), "already in progress") {
			t.Fatalf("drain failed unexpectedly: %v", err)
		}
	}
	requireUniqueSequences(t, readRecording(t, paths, segment.ID), total)
}

func TestSealRequiresEmptyBufferAndVerification(t *testing.T) {
	manager, _ := newTestManager(t)
	segment := startSegment(t, manager, 5, 128)

	if _, err := manager.Seal(segment.ID, "too early"); err == nil {
		t.Fatal("seal succeeded with buffered frames")
	}
	preview, err := manager.SealPreview(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Ready || len(preview.Blockers) == 0 {
		t.Fatalf("preview should block seal with buffered frames: %+v", preview)
	}
	if preview.Progress.FramesBuffered != 5 {
		t.Fatalf("preview shows %d buffered, want 5", preview.Progress.FramesBuffered)
	}

	outcome, err := manager.Drain(context.Background(), segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Drained != 5 || !outcome.Progress.SealReady {
		t.Fatalf("unexpected drain outcome: %+v", outcome)
	}

	preview, err = manager.SealPreview(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Ready {
		t.Fatalf("preview not ready after drain: %v", preview.Blockers)
	}
	if !preview.Progress.Verified || preview.Progress.FileCRC32 == 0 {
		t.Fatalf("preview missing verification: %+v", preview.Progress)
	}

	result, err := manager.Seal(segment.ID, "pass complete")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !result.Verification.OK || result.Verification.Frames != 5 {
		t.Fatalf("unexpected seal result: %+v", result)
	}
	if result.Verification.CRC32 != preview.Progress.FileCRC32 {
		t.Fatalf("seal checksum %08x differs from preview %08x", result.Verification.CRC32, preview.Progress.FileCRC32)
	}
	if result.Segment.Status != Sealed || result.Segment.SealReason != "pass complete" {
		t.Fatalf("unexpected sealed segment: %+v", result.Segment)
	}
	if _, err := manager.Seal(segment.ID, "again"); err == nil {
		t.Fatal("second seal unexpectedly succeeded")
	}
}

func TestSealRejectedWhenRecordingCorrupted(t *testing.T) {
	manager, paths := newTestManager(t)
	segment := startSegment(t, manager, 3, 128)
	if _, err := manager.Drain(context.Background(), segment.ID); err != nil {
		t.Fatal(err)
	}

	// Flip one payload byte inside the first frame record.
	path := paths.Recording(segment.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[frameHeaderSize+7] ^= 0xFF
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	progress, err := manager.DrainProgress(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Verified || !strings.Contains(progress.VerifyError, "checksum") {
		t.Fatalf("corruption went unnoticed: %+v", progress)
	}
	preview, err := manager.SealPreview(segment.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Ready {
		t.Fatal("preview ready despite corrupted recording")
	}
	result, err := manager.Seal(segment.ID, "should fail")
	if err == nil {
		t.Fatal("seal succeeded on corrupted recording")
	}
	if result.Complete || result.Verification.OK {
		t.Fatalf("unexpected seal result on corruption: %+v", result)
	}
	for _, value := range manager.List() {
		if value.ID == segment.ID && value.Status == Sealed {
			t.Fatal("corrupted recording was sealed")
		}
	}
}
