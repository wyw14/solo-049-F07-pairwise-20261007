package recorder

import (
	"fmt"

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
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.OwnerStation != station || current.segment.OwnerGeneration != expectedGeneration {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "stale-close.ignored", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"station": station, "expected_generation": expectedGeneration, "current_generation": current.segment.OwnerGeneration}})
		return nil
	}
	if len(current.buffer) > 0 {
		return fmt.Errorf("owner close rejected while %d frames remain buffered", len(current.buffer))
	}
	verification := m.writer.Verify(segmentID)
	if !verification.OK {
		return fmt.Errorf("owner close rejected: file verification failed: %s", verification.Error)
	}
	if verification.Frames != current.segment.FramesWritten {
		return fmt.Errorf("owner close rejected: recording file holds %d frames but %d are accounted written", verification.Frames, current.segment.FramesWritten)
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	return m.flushLocked()
}
