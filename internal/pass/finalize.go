package pass

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
)

type FinalizeResult struct {
	PassID        string                 `json:"pass_id"`
	UnlockError   string                 `json:"unlock_error,omitempty"`
	FramesDrained int                    `json:"frames_drained"`
	Drain         recorder.DrainProgress `json:"drain"`
	Seal          recorder.SealResult    `json:"seal"`
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
	outcome, drainErr := f.recorder.Drain(ctx, value.RecordingSegmentID)
	result.FramesDrained = outcome.Drained
	result.Drain = outcome.Progress
	if drainErr != nil {
		return result, drainErr
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
	_, _ = f.audit.Record(audit.Event{Component: "pass", Action: "finalized", Subject: passID, Fields: map[string]any{"frames_drained": result.FramesDrained, "unlock_error": result.UnlockError}})
	return result, nil
}
