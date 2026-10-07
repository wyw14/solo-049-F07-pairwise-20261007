package recorder

import (
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

func (m *Manager) Transfer(segmentID, from, to string, expectedGeneration int64) (Segment, error) {
	if from == "" || to == "" || from == to {
		return Segment{}, fmt.Errorf("distinct source and destination owners are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return Segment{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.OwnerStation != from || current.segment.OwnerGeneration != expectedGeneration {
		return Segment{}, fmt.Errorf("recording owner generation changed")
	}
	current.segment.OwnerStation = to
	current.segment.OwnerGeneration++
	if err := m.flushLocked(); err != nil {
		return Segment{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "ownership.transferred", Subject: segmentID, Fields: map[string]any{"from": from, "to": to, "generation": current.segment.OwnerGeneration}})
	return current.segment, nil
}

func (m *Manager) CloseForOwner(segmentID, station string, expectedGeneration int64, reason string) error {
	m.mu.RLock()
	session, found := m.sessions[segmentID]
	if !found {
		m.mu.RUnlock()
		return fmt.Errorf("recording segment %s not found", segmentID)
	}
	m.mu.RUnlock()

	// Serialize against an in-flight drain just like Seal.
	session.drain.Lock()
	defer session.drain.Unlock()

	m.mu.Lock()
	current := m.sessions[segmentID]
	if current.segment.OwnerStation != station || current.segment.OwnerGeneration != expectedGeneration {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "stale-close.ignored", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "expected_generation": expectedGeneration, "current_generation": current.segment.OwnerGeneration}})
		m.mu.Unlock()
		return nil
	}
	if len(current.buffer) > 0 {
		m.mu.Unlock()
		return fmt.Errorf("owner close rejected while %d frames remain buffered", len(current.buffer))
	}
	written := current.segment.FramesWritten
	m.mu.Unlock()

	// Seal through the same rule as Manager.Seal: empty buffer alone is not
	// enough, the recording file must also verify.
	report, err := m.writer.Verify(segmentID)
	if err != nil {
		return err
	}
	if !report.Healthy() {
		if report.Error != "" {
			return fmt.Errorf("owner close rejected: %s", report.Error)
		}
		return fmt.Errorf("owner close rejected: %d corrupt trailing bytes", report.TailBytes)
	}
	if report.FramesOnDisk != written {
		return fmt.Errorf("owner close rejected: file holds %d frames, counter says %d", report.FramesOnDisk, written)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	current = m.sessions[segmentID]
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = time.Now().UTC()
	current.segment.FileBytes = report.Bytes
	current.segment.ChecksumSHA256 = report.SHA256
	current.segment.VerifyError = ""
	return m.flushLocked()
}
