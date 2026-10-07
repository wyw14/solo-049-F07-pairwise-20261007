package pass

import (
	"context"
	"fmt"
	"strings"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
)

type FinalizeResult struct {
	PassID        string               `json:"pass_id"`
	UnlockError   string               `json:"unlock_error,omitempty"`
	Drain         recorder.DrainResult `json:"drain"`
	FramesDrained int                  `json:"frames_drained"`
	Preview       recorder.SealPreview `json:"seal_preview"`
	Seal          recorder.SealResult  `json:"seal"`
}

type Finalizer struct {
	passes        *Service
	recorder      *recorder.Manager
	unlocker      *receiver.Unlocker
	audit         *audit.Trail
	unlockTimeout time.Duration
}

func NewFinalizer(passes *Service, manager *recorder.Manager, unlocker *receiver.Unlocker, trail *audit.Trail, unlockTimeout time.Duration) *Finalizer {
	return &Finalizer{passes: passes, recorder: manager, unlocker: unlocker, audit: trail, unlockTimeout: unlockTimeout}
}

func (f *Finalizer) Finalize(ctx context.Context, passID, chainID string) (FinalizeResult, error) {
	value, found := f.passes.Get(passID)
	if !found {
		return FinalizeResult{}, fmt.Errorf("pass %s not found", passID)
	}
	if value.RecordingSegmentID == "" {
		return FinalizeResult{}, fmt.Errorf("pass %s has no recording segment", passID)
	}
	if err := f.passes.update(passID, func(current *Pass) error {
		current.Phase = Draining
		return nil
	}); err != nil {
		return FinalizeResult{}, err
	}
	unlockContext, cancelUnlock := context.WithTimeout(ctx, f.unlockTimeout)
	unlockErr := f.unlocker.Unlock(unlockContext, chainID, passID)
	cancelUnlock()

	result := FinalizeResult{PassID: passID}
	if unlockErr != nil {
		result.UnlockError = unlockErr.Error()
	}
	drain, drainErr := f.recorder.Drain(ctx, value.RecordingSegmentID)
	result.Drain = drain
	result.FramesDrained = drain.WrittenThisRun
	if drainErr != nil {
		// Keep the seal preview so callers see the exact written/unwritten
		// boundary even when the drain was canceled mid-flight.
		result.Preview, _ = f.recorder.PreviewSeal(value.RecordingSegmentID)
		return result, drainErr
	}
	preview, err := f.recorder.PreviewSeal(value.RecordingSegmentID)
	result.Preview = preview
	if err != nil {
		return result, err
	}
	if !preview.Ready {
		return result, fmt.Errorf("recording segment %s not ready to seal: %s", value.RecordingSegmentID, strings.Join(preview.Blockers, "; "))
	}
	seal, err := f.recorder.Seal(value.RecordingSegmentID, "pass LOS complete")
	result.Seal = seal
	if err != nil {
		return result, err
	}
	if err := f.passes.update(passID, func(current *Pass) error {
		current.Phase = Completed
		return nil
	}); err != nil {
		return result, err
	}
	_, _ = f.audit.Record(audit.Event{Component: "pass", Action: "finalized", Subject: passID, Fields: map[string]any{"frames_drained": drain.FramesWritten, "unlock_error": result.UnlockError, "sha256": preview.ChecksumSHA256}})
	return result, nil
}
