package recorder

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

// Drain writes buffered frames to the recording file.
//
// The file is the source of truth for the written/unwritten boundary: before
// appending anything the recording is scanned and any torn trailing frame is
// trimmed, so frames already on disk are skipped. A canceled or failed drain
// commits only the frames confirmed durable; everything after that boundary
// stays buffered. Re-running Drain therefore never writes a frame twice.
func (m *Manager) Drain(ctx context.Context, segmentID string) (DrainResult, error) {
	m.mu.RLock()
	session, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return DrainResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if session.segment.Status != Open && session.segment.Status != Draining {
		status := session.segment.Status
		m.mu.RUnlock()
		return DrainResult{}, fmt.Errorf("recording segment %s cannot drain from %s", segmentID, status)
	}
	m.mu.RUnlock()

	// Serialize drains of this segment; sequence reconciliation makes a
	// queued second drain a no-op for frames the first one committed.
	session.drain.Lock()
	defer session.drain.Unlock()

	m.mu.Lock()
	current := m.sessions[segmentID]
	if current.segment.Status != Open && current.segment.Status != Draining {
		status := current.segment.Status
		m.mu.Unlock()
		return DrainResult{}, fmt.Errorf("recording segment %s cannot drain from %s", segmentID, status)
	}
	current.segment.Status = Draining
	total := len(current.buffer)
	if err := m.flushLocked(); err != nil {
		m.mu.Unlock()
		return DrainResult{}, err
	}
	m.mu.Unlock()

	result := DrainResult{SegmentID: segmentID, Status: Draining, Total: total}

	// Reconcile to the durable prefix: trim a torn tail from a previous
	// interrupted append, then match the file against the buffer head by
	// frame sequence. Anything already on disk is skipped on retry.
	report, err := m.repairFile(segmentID)
	if err != nil {
		return result, err
	}
	m.mu.Lock()
	current = m.sessions[segmentID]
	matched, divergence := matchedPrefix(current.buffer, report.Sequences)
	if divergence != "" {
		m.mu.Unlock()
		return result, fmt.Errorf("recording segment %s diverged from buffer: %s", segmentID, divergence)
	}
	pending := append([]Frame(nil), current.buffer[matched:]...)
	m.mu.Unlock()

	canceled := false
	var writeErr error
	var loopAppended int
	for _, frame := range pending {
		if err := ctx.Err(); err != nil {
			canceled = true
			writeErr = err
			break
		}
		if _, err := m.writer.Append(segmentID, frame); err != nil {
			writeErr = err
			break
		}
		loopAppended++
	}

	// Re-scan instead of trusting the last Append: a failed write can have
	// landed a partial record, and only a full rescan pins the exact boundary.
	initialMatched := matched
	finalReport, verifyErr := m.repairFile(segmentID)
	switch {
	case verifyErr == nil:
		m.mu.Lock()
		current = m.sessions[segmentID]
		endMatched, endDivergence := matchedPrefix(current.buffer, finalReport.Sequences)
		m.mu.Unlock()
		if endDivergence != "" {
			return result, fmt.Errorf("recording segment %s diverged after drain: %s", segmentID, endDivergence)
		}
		matched = endMatched
	default:
		// Rescan itself failed (I/O error, not corruption). Fall back to the
		// fsynced append count, which is a safe lower bound.
		matched = initialMatched + loopAppended
	}

	m.mu.Lock()
	current = m.sessions[segmentID]
	if matched > len(current.buffer) {
		matched = len(current.buffer)
	}
	committedThisRun := matched - initialMatched
	if committedThisRun < 0 {
		committedThisRun = 0
	}
	// Frames beyond the buffer that are already durable (for example after a
	// restart that reloaded the segment without its in-memory buffer) still
	// count toward the on-disk total.
	durableBeyondBuffer := finalReport.FramesOnDisk - matched
	if durableBeyondBuffer < 0 {
		durableBeyondBuffer = 0
	}
	framesWritten := matched + durableBeyondBuffer
	current.buffer = current.buffer[matched:]
	current.segment.Status = Draining
	current.segment.FramesWritten = framesWritten
	current.segment.FramesBuffered = len(current.buffer)
	fileConfirmed := verifyErr == nil
	if fileConfirmed {
		current.segment.FileBytes = finalReport.Bytes
		if finalReport.Healthy() {
			current.segment.VerifyError = ""
			if len(current.buffer) == 0 {
				current.segment.ChecksumSHA256 = finalReport.SHA256
			}
		} else if finalReport.Error != "" {
			current.segment.VerifyError = finalReport.Error
		}
	}
	flushErr := m.flushLocked()
	m.mu.Unlock()

	result.WrittenThisRun = committedThisRun
	result.FramesWritten = framesWritten
	result.Remaining = len(current.buffer)
	result.Total = framesWritten + result.Remaining
	if fileConfirmed {
		result.BytesOnDisk = finalReport.Bytes
	} else {
		result.BytesOnDisk = report.Bytes
	}
	result.Complete = fileConfirmed && result.Remaining == 0 && finalReport.Healthy()
	if result.Complete {
		result.ChecksumSHA256 = finalReport.SHA256
	}
	result.Canceled = canceled
	if writeErr != nil {
		result.Error = writeErr.Error()
	} else if verifyErr != nil {
		result.Error = verifyErr.Error()
	} else if flushErr != nil {
		result.Error = flushErr.Error()
	}

	switch {
	case writeErr != nil:
		action := "drain.failed"
		if canceled {
			action = "drain.canceled"
		}
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: action, Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"committed": framesWritten, "remaining": result.Remaining, "error": writeErr.Error()}})
		return result, fmt.Errorf("recorder drain stopped after %d frames with %d buffered: %w", framesWritten, result.Remaining, writeErr)
	case verifyErr != nil:
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drain.verify_failed", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"error": verifyErr.Error()}})
		return result, verifyErr
	case flushErr != nil:
		return result, flushErr
	default:
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drained", Subject: segmentID, Fields: map[string]any{"frames": result.WrittenThisRun, "remaining": result.Remaining, "complete": result.Complete}})
		return result, nil
	}
}

// repairFile scans the recording and trims a torn trailing frame so the file
// ends on a frame boundary. The returned report describes the intact prefix.
func (m *Manager) repairFile(segmentID string) (VerifyReport, error) {
	report, err := m.writer.Verify(segmentID)
	if err != nil {
		return report, err
	}
	if report.TailBytes > 0 {
		if err := m.writer.Trim(segmentID, report.ValidBytes); err != nil {
			return report, err
		}
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "tail.trimmed", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"bytes": report.TailBytes, "valid_bytes": report.ValidBytes}})
		report, err = m.writer.Verify(segmentID)
		if err != nil {
			return report, err
		}
	}
	return report, nil
}

// PreviewSeal reports whether the segment is ready to seal without changing
// anything: the buffer must be empty and the recording file must verify.
func (m *Manager) PreviewSeal(segmentID string) (SealPreview, error) {
	m.mu.RLock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return SealPreview{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	preview := SealPreview{
		SegmentID:     segmentID,
		Status:        current.segment.Status,
		FramesWritten: current.segment.FramesWritten,
		Remaining:     len(current.buffer),
		BytesOnDisk:   current.segment.FileBytes,
		Blockers:      []string{},
	}
	storedChecksum := current.segment.ChecksumSHA256
	m.mu.RUnlock()

	report, err := m.writer.Verify(segmentID)
	if err != nil {
		return preview, err
	}
	preview.BytesOnDisk = report.Bytes
	preview.Verified = report.Healthy()
	preview.ChecksumSHA256 = report.SHA256

	if preview.Status == Sealed {
		preview.Blockers = append(preview.Blockers, "segment is already sealed")
		if storedChecksum != "" && storedChecksum != report.SHA256 {
			preview.Blockers = append(preview.Blockers, fmt.Sprintf("sealed checksum %s no longer matches file %s", storedChecksum, report.SHA256))
			preview.Verified = false
		}
	}
	if preview.Remaining > 0 {
		preview.Blockers = append(preview.Blockers, fmt.Sprintf("%d frames remain buffered", preview.Remaining))
	}
	if report.Error != "" {
		preview.VerifyError = report.Error
		preview.Blockers = append(preview.Blockers, "recording verification failed: "+report.Error)
	} else if report.TailBytes > 0 {
		preview.VerifyError = fmt.Sprintf("%d corrupt trailing bytes beyond byte %d", report.TailBytes, report.ValidBytes)
		preview.Blockers = append(preview.Blockers, preview.VerifyError)
	}
	if report.Healthy() && report.FramesOnDisk != preview.FramesWritten {
		preview.Blockers = append(preview.Blockers, fmt.Sprintf("frame count mismatch: file holds %d, counter says %d", report.FramesOnDisk, preview.FramesWritten))
	}
	preview.Ready = preview.Status != Sealed && len(preview.Blockers) == 0
	return preview, nil
}

// Seal closes a segment. It is allowed only when the buffer is empty and the
// recording file passes frame/CRC verification. The SHA-256 of the verified
// file is recorded as the seal attestation.
func (m *Manager) Seal(segmentID, reason string) (SealResult, error) {
	m.mu.RLock()
	session, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	m.mu.RUnlock()

	// Do not seal against a drain mid-flight; wait for its committed boundary.
	session.drain.Lock()
	defer session.drain.Unlock()

	m.mu.Lock()
	current := m.sessions[segmentID]
	if current.segment.Status == Sealed {
		segment := current.segment
		m.mu.Unlock()
		return SealResult{Segment: segment, Complete: true}, nil
	}
	if len(current.buffer) != 0 {
		segment := current.segment
		m.mu.Unlock()
		return SealResult{Segment: segment, Complete: false, Error: fmt.Sprintf("%d frames remain buffered", len(current.buffer))}, fmt.Errorf("recording still has %d buffered frames", len(current.buffer))
	}
	buffered := len(current.buffer)
	written := current.segment.FramesWritten
	m.mu.Unlock()

	// No trimming during seal: verification must pass on the file as-is.
	report, err := m.writer.Verify(segmentID)
	if err != nil {
		return SealResult{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	current, found = m.sessions[segmentID]
	if !found {
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if len(current.buffer) != buffered {
		return SealResult{Segment: current.segment, Complete: false, Error: "buffer changed during seal verification"}, fmt.Errorf("recording segment %s buffer changed during seal", segmentID)
	}
	if !report.Healthy() {
		current.segment.VerifyError = report.Error
		message := "recording verification failed"
		if report.Error != "" {
			message = report.Error
		}
		_ = m.flushLocked()
		return SealResult{Segment: current.segment, Complete: false, Error: message}, fmt.Errorf("cannot seal segment %s: %s", segmentID, message)
	}
	if report.FramesOnDisk != written {
		message := fmt.Sprintf("frame count mismatch: file holds %d, counter says %d", report.FramesOnDisk, written)
		return SealResult{Segment: current.segment, Complete: false, Error: message}, fmt.Errorf("cannot seal segment %s: %s", segmentID, message)
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = time.Now().UTC()
	current.segment.FileBytes = report.Bytes
	current.segment.ChecksumSHA256 = report.SHA256
	current.segment.VerifyError = ""
	if err := m.flushLocked(); err != nil {
		return SealResult{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "sealed", Subject: segmentID, Fields: map[string]any{"frames": current.segment.FramesWritten, "reason": reason, "sha256": report.SHA256}})
	return SealResult{Segment: current.segment, Complete: true}, nil
}
