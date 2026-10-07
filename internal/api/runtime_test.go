package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	stationclock "orbitlink/internal/clock"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/rf"
	"orbitlink/internal/satellite"
	"orbitlink/internal/weather"
)

func TestOperationsPagesAndAPIsUseRuntimeState(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	for _, target := range []string{"/passes", "/antennas", "/rf-chains", "/recordings", "/healthz", "/api/passes", "/api/antennas", "/api/rf-chains", "/api/recordings"} {
		response, err := server.Client().Get(server.URL + target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d", target, response.StatusCode)
		}
		_ = response.Body.Close()
	}
}

func TestPassRevisionAcquisitionAndRecordingFlow(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-01", CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-02", CenterHz: 2_245_000_000, DopplerHz: 12_050, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
	attempt, err := runtime.Attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Passes.BeginAcquisition(value.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	results := []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 7},
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 7},
	}
	decision, err := runtime.Passes.AcceptDiversity(value.ID, results)
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	active, found := runtime.Recorder.ActiveForPass(value.ID)
	if !found {
		t.Fatal("tracking did not start a recorder")
	}
	session, err := runtime.NewDecoderSession(value.ID, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OnLock(attempt.ID); err != nil {
		t.Fatal(err)
	}
	if written, err := session.Feed(attempt.ID, make([]byte, 128)); err != nil || written != 2 {
		t.Fatalf("decoder feed wrote %d frames: %v", written, err)
	}
	if _, err := runtime.Recorder.Drain(context.Background(), active.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Recorder.Seal(active.ID, "integration complete"); err != nil {
		t.Fatal(err)
	}
}

func TestEphemerisClockAndWindSafetyFlow(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]
	previous, _ := runtime.Ephemerides.Current(value.SatelliteID)
	if _, err := runtime.Ephemerides.Import(satellite.Ephemeris{SatelliteID: value.SatelliteID, Revision: previous.Revision + 1, Epoch: time.Now().UTC(), Line1: "revised orbital element one", Line2: "revised orbital element two"}); err != nil {
		t.Fatal(err)
	}
	commands := runtime.Commands.List(value.ID)
	if len(commands) == 0 || commands[len(commands)-1].Revision != previous.Revision+1 {
		t.Fatal("revised pointing commands were not queued")
	}
	if _, err := runtime.Clock.Apply(stationclock.Sample{ObservedAt: time.Now().UTC(), Offset: 2 * time.Second, Source: "gps", Quality: "locked"}); err != nil {
		t.Fatal(err)
	}
	if len(runtime.Clock.Corrections()) != 1 {
		t.Fatal("clock correction was not persisted")
	}
	if err := runtime.RF.EnableTransmit("RF-01"); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Weather.Handle(context.Background(), weather.WindSample{StationID: "station", GustMetersPerSecond: 25, ObservedAt: time.Now().UTC()}, value.ID, value.AntennaID, "RF-01")
	if err != nil || !result.InhibitConfirmed || !result.Stowed {
		t.Fatalf("wind safety did not converge: %#v %v", result, err)
	}
}

func TestRecordingDrainProgressAndSealEndpoints(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()

	segment, err := runtime.Recorder.Start("pass-endpoint", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	base := server.URL + "/api/recordings/" + segment.ID

	for _, body := range []string{`{"sequence":1,"epoch":7,"size":64}`, `{"sequence":2,"epoch":7,"size":64}`} {
		response := requestJSON(t, server.Client(), http.MethodPost, base+"/frames", body)
		if response.StatusCode != http.StatusAccepted {
			t.Fatalf("append frame returned %d", response.StatusCode)
		}
		_ = response.Body.Close()
	}

	// Sealing is rejected while frames remain buffered.
	response := requestJSON(t, server.Client(), http.MethodPost, base+"/seal", `{"reason":"too early"}`)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("seal with buffered frames returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = server.Client().Get(base + "/progress")
	if err != nil {
		t.Fatal(err)
	}
	var progress recorder.DrainProgress
	decodeBody(t, response, &progress)
	if progress.FramesBuffered != 2 || progress.FramesWritten != 0 || progress.SealReady {
		t.Fatalf("unexpected progress: %+v", progress)
	}

	response, err = server.Client().Get(base + "/seal-preview")
	if err != nil {
		t.Fatal(err)
	}
	var preview recorder.SealPreview
	decodeBody(t, response, &preview)
	if preview.Ready || len(preview.Blockers) == 0 {
		t.Fatalf("preview should not be ready with buffered frames: %+v", preview)
	}

	response = requestJSON(t, server.Client(), http.MethodPost, base+"/drain", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("drain returned %d", response.StatusCode)
	}
	var outcome recorder.DrainOutcome
	decodeBody(t, response, &outcome)
	if outcome.Drained != 2 || !outcome.Progress.SealReady || !outcome.Progress.Verified {
		t.Fatalf("unexpected drain outcome: %+v", outcome)
	}

	response, err = server.Client().Get(base + "/seal-preview")
	if err != nil {
		t.Fatal(err)
	}
	decodeBody(t, response, &preview)
	if !preview.Ready {
		t.Fatalf("preview not ready after drain: %v", preview.Blockers)
	}

	response = requestJSON(t, server.Client(), http.MethodPost, base+"/seal", `{"reason":"endpoint test"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("seal returned %d", response.StatusCode)
	}
	var result recorder.SealResult
	decodeBody(t, response, &result)
	if !result.Complete || !result.Verification.OK || result.Verification.Frames != 2 {
		t.Fatalf("unexpected seal result: %+v", result)
	}

	response = requestJSON(t, server.Client(), http.MethodPost, base+"/seal", `{"reason":"again"}`)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("second seal returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestRouterRejectsOverlappingReservation(t *testing.T) {
	runtime := newTestRuntime(t)
	first := runtime.Passes.List()[0]
	second, err := runtime.Passes.Create(passsvc.CreateRequest{SatelliteID: "SAT-C07", AntennaID: first.AntennaID, RFChains: []string{"RF-03"}, RequiredReceiverChains: []string{"RF-03"}, AOS: first.Window.AOS.Add(time.Minute), LOS: first.Window.LOS.Add(time.Minute), Revision: 1, OwnerStation: "north"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.WindowRecompute.Apply(second.ID, second.Window); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Reservations.ReservePass(second.ID, second.AntennaID); err == nil {
		t.Fatal("overlapping reservation unexpectedly succeeded")
	}
}

func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func decodeBody(t *testing.T, response *http.Response, value any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(value); err != nil {
		t.Fatal(err)
	}
}

func requestJSON(t *testing.T, client *http.Client, method, target, payload string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
