package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"orbitlink/internal/audit"
	"orbitlink/internal/decoder"
	"orbitlink/internal/recorder"
)

func (r *Runtime) listRecordings(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Recorder.List()})
}

func (r *Runtime) drainProgress(writer http.ResponseWriter, request *http.Request) {
	progress, err := r.Recorder.DrainProgress(chi.URLParam(request, "segmentID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, progress)
}

func (r *Runtime) drainRecording(writer http.ResponseWriter, request *http.Request) {
	outcome, err := r.Recorder.Drain(request.Context(), chi.URLParam(request, "segmentID"))
	if err != nil {
		// A canceled or failed drain still commits its written/unwritten
		// boundary; return the outcome so callers can see where it stopped.
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "status": http.StatusUnprocessableEntity, "outcome": outcome})
		return
	}
	writeJSON(writer, http.StatusOK, outcome)
}

func (r *Runtime) sealPreview(writer http.ResponseWriter, request *http.Request) {
	preview, err := r.Recorder.SealPreview(chi.URLParam(request, "segmentID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, preview)
}

func (r *Runtime) sealRecording(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Reason string `json:"reason"`
	}
	if request.ContentLength > 0 {
		if err := decodeJSON(request, &input); err != nil {
			writeError(writer, err)
			return
		}
	}
	if input.Reason == "" {
		input.Reason = "manual seal"
	}
	result, err := r.Recorder.Seal(chi.URLParam(request, "segmentID"), input.Reason)
	if err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "status": http.StatusUnprocessableEntity, "result": result})
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (r *Runtime) appendFrame(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Sequence uint64 `json:"sequence"`
		Epoch    int64  `json:"epoch"`
		Size     int    `json:"size"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	if input.Size == 0 {
		input.Size = 64
	}
	payload := decoder.EncodeTelemetry(input.Sequence, input.Size)
	err := r.Recorder.Buffer(chi.URLParam(request, "segmentID"), recorder.Frame{Sequence: input.Sequence, Epoch: input.Epoch, Received: time.Now().UTC(), Payload: payload})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"buffered": true, "sequence": input.Sequence})
}

func (r *Runtime) listAudit(writer http.ResponseWriter, request *http.Request) {
	values := r.Audit.List(audit.Query{Component: request.URL.Query().Get("component"), Subject: request.URL.Query().Get("subject"), Limit: 100})
	writeJSON(writer, http.StatusOK, map[string]any{"items": values})
}

func (r *Runtime) listPersistentEvents(writer http.ResponseWriter, request *http.Request) {
	values, err := r.EventLog.Read(chi.URLParam(request, "stream"), 100)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": values})
}

func (r *Runtime) handoverPass(writer http.ResponseWriter, request *http.Request) {
	id := chi.URLParam(request, "passID")
	var input struct {
		Destination string `json:"destination"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	value, err := r.RequirePass(id)
	if err != nil {
		writeError(writer, err)
		return
	}
	segment, found := r.Recorder.ActiveForPass(id)
	if !found || value.RecordingSegmentID == "" {
		writeError(writer, errMessage("pass has no active recording"))
		return
	}
	session, err := r.Handovers.Begin(id, segment.ID, value.OwnerStation, input.Destination, value.OwnerGeneration)
	if err != nil {
		writeError(writer, err)
		return
	}
	session, err = r.Handovers.Transfer(session.ID)
	if err != nil {
		writeError(writer, err)
		return
	}
	if err := session.ValidateTransferred(); err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, session)
}

func (r *Runtime) cleanupHandover(writer http.ResponseWriter, request *http.Request) {
	if err := r.Handovers.Cleanup(chi.URLParam(request, "sessionID")); err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"cleaned": true})
}

func (r *Runtime) lockReceiver(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		AttemptID string `json:"attempt_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	session, err := r.receiverSession(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	epoch, err := session.OnLock(input.AttemptID)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"epoch": epoch})
}

func (r *Runtime) loseCarrier(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		AttemptID string `json:"attempt_id"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	session, err := r.receiverSession(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	if err := session.OnCarrierLoss(input.AttemptID); err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"carrier_lost": true})
}

func (r *Runtime) feedSymbols(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		AttemptID string `json:"attempt_id"`
		Symbols   []byte `json:"symbols"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	session, err := r.receiverSession(chi.URLParam(request, "passID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	frames, err := session.Feed(input.AttemptID, input.Symbols)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"frames_buffered": frames})
}

func (r *Runtime) listClockCorrections(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Clock.Corrections()})
}
