package recorder

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

// Drain flushes buffered frames to the recording file. The written/unwritten
// boundary is committed on every exit path — success, cancellation and write
// failure — so a retry always resumes at the first unwritten frame and never
// appends a frame twice. Only one drain may run per segment at a time.
func (m *Manager) Drain(ctx context.Context, segmentID string) (DrainOutcome, error) {
	m.mu.Lock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.Unlock()
		return DrainOutcome{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.Status != Open && current.segment.Status != Draining {
		m.mu.Unlock()
		return DrainOutcome{}, fmt.Errorf("recording segment %s cannot drain from %s", segmentID, current.segment.Status)
	}
	if current.draining {
		m.mu.Unlock()
		return DrainOutcome{}, fmt.Errorf("recording segment %s drain already in progress", segmentID)
	}
	current.draining = true
	current.segment.Status = Draining
	frames := append([]Frame(nil), current.buffer...)
	m.mu.Unlock()

	written := 0
	canceled := false
	var drainErr error
	for _, frame := range frames {
		select {
		case <-ctx.Done():
			canceled = true
			drainErr = fmt.Errorf("recorder drain canceled after %d of %d frames: %w", written, len(frames), ctx.Err())
		default:
		}
		if canceled {
			break
		}
		if err := m.writer.Append(segmentID, frame); err != nil {
			drainErr = err
			break
		}
		written++
	}

	// Commit the boundary no matter how the loop ended: frames already
	// appended leave the buffer here, everything else stays for the retry.
	m.mu.Lock()
	current.draining = false
	current.buffer = current.buffer[written:]
	current.segment.FramesWritten += written
	current.segment.FramesBuffered = len(current.buffer)
	current.lastDrained = written
	flushErr := m.flushLocked()
	segment := current.segment
	buffered := len(current.buffer)
	m.mu.Unlock()

	if flushErr == nil {
		event := audit.Event{Component: "recorder", Action: "drained", Subject: segmentID, Fields: map[string]any{
			"frames": written, "frames_written": segment.FramesWritten, "remaining": buffered, "canceled": canceled,
		}}
		if drainErr != nil {
			event.Severity = audit.Warning
		}
		_, _ = m.audit.Record(event)
	}
	outcome := DrainOutcome{
		Drained:  written,
		Canceled: canceled,
		Progress: progressFor(segment, buffered, written, m.writer.Verify(segmentID)),
	}
	if drainErr != nil {
		return outcome, drainErr
	}
	return outcome, flushErr
}

// DrainProgress reports the current drain and verification snapshot for a
// segment without changing any state.
func (m *Manager) DrainProgress(segmentID string) (DrainProgress, error) {
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return DrainProgress{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	segment := current.segment
	buffered := len(current.buffer)
	lastDrained := current.lastDrained
	m.mu.RUnlock()
	return progressFor(segment, buffered, lastDrained, m.writer.Verify(segmentID)), nil
}

// SealPreview reports whether Seal would succeed right now, listing every
// blocker, without changing any state.
func (m *Manager) SealPreview(segmentID string) (SealPreview, error) {
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return SealPreview{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	segment := current.segment
	buffered := len(current.buffer)
	lastDrained := current.lastDrained
	m.mu.RUnlock()
	progress := progressFor(segment, buffered, lastDrained, m.writer.Verify(segmentID))
	preview := SealPreview{Segment: segment, Progress: progress}
	switch segment.Status {
	case Sealed:
		preview.Blockers = append(preview.Blockers, "segment is already sealed")
	case Aborted:
		preview.Blockers = append(preview.Blockers, "segment is aborted")
	}
	if buffered > 0 {
		preview.Blockers = append(preview.Blockers, fmt.Sprintf("%d frames remain buffered", buffered))
	}
	if progress.VerifyError != "" {
		preview.Blockers = append(preview.Blockers, "file verification failed: "+progress.VerifyError)
	}
	preview.Ready = len(preview.Blockers) == 0
	return preview, nil
}

// Seal closes a segment for good. Sealing is only allowed once the buffer is
// empty and the recording file verifies: every frame record must carry a
// valid CRC32 and the file must hold exactly the frames accounted as written.
func (m *Manager) Seal(segmentID, reason string) (SealResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	switch current.segment.Status {
	case Sealed:
		return SealResult{Segment: current.segment, Error: "already sealed"}, fmt.Errorf("recording segment %s is already sealed", segmentID)
	case Aborted:
		return SealResult{Segment: current.segment, Error: "aborted"}, fmt.Errorf("recording segment %s is aborted", segmentID)
	}
	if len(current.buffer) != 0 {
		return SealResult{Segment: current.segment, Complete: false, Error: "frames remain buffered"}, fmt.Errorf("recording still has %d buffered frames", len(current.buffer))
	}
	verification := m.writer.Verify(segmentID)
	if !verification.OK {
		return SealResult{Segment: current.segment, Complete: false, Verification: verification, Error: "file verification failed: " + verification.Error},
			fmt.Errorf("recording segment %s failed verification: %s", segmentID, verification.Error)
	}
	if verification.Frames != current.segment.FramesWritten {
		mismatch := fmt.Sprintf("recording file holds %d frames but %d are accounted written", verification.Frames, current.segment.FramesWritten)
		return SealResult{Segment: current.segment, Complete: false, Verification: verification, Error: mismatch},
			fmt.Errorf("recording segment %s: %s", segmentID, mismatch)
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = time.Now().UTC()
	if err := m.flushLocked(); err != nil {
		return SealResult{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "sealed", Subject: segmentID, Fields: map[string]any{
		"frames": current.segment.FramesWritten, "reason": reason, "file_crc32": verification.CRC32, "file_bytes": verification.Bytes,
	}})
	return SealResult{Segment: current.segment, Complete: true, Verification: verification}, nil
}

// progressFor combines the accounted segment state with a fresh file
// verification. Verified means the file checksum pass succeeded and the file
// holds exactly the frames accounted as written; SealReady additionally
// requires an empty buffer and a live segment.
func progressFor(segment Segment, buffered, lastDrained int, verification FileVerification) DrainProgress {
	progress := DrainProgress{
		SegmentID:      segment.ID,
		Status:         segment.Status,
		FramesWritten:  segment.FramesWritten,
		FramesBuffered: buffered,
		LastDrained:    lastDrained,
		FileBytes:      verification.Bytes,
		FileCRC32:      verification.CRC32,
	}
	switch {
	case !verification.OK:
		progress.VerifyError = verification.Error
	case verification.Frames != segment.FramesWritten:
		progress.VerifyError = fmt.Sprintf("recording file holds %d frames but %d are accounted written", verification.Frames, segment.FramesWritten)
	}
	progress.Verified = progress.VerifyError == ""
	progress.SealReady = progress.Verified && buffered == 0 && segment.Status != Sealed && segment.Status != Aborted
	return progress
}
