package recorder

import "time"

type SegmentStatus string

const (
	Open     SegmentStatus = "open"
	Draining SegmentStatus = "draining"
	Sealed   SegmentStatus = "sealed"
	Aborted  SegmentStatus = "aborted"
)

type Frame struct {
	Sequence uint64    `json:"sequence"`
	Epoch    int64     `json:"epoch"`
	Received time.Time `json:"received"`
	Payload  []byte    `json:"payload"`
	CRC32    uint32    `json:"crc32"`
}

type Segment struct {
	ID              string        `json:"id"`
	PassID          string        `json:"pass_id"`
	OwnerStation    string        `json:"owner_station"`
	OwnerGeneration int64         `json:"owner_generation"`
	Status          SegmentStatus `json:"status"`
	FramesWritten   int           `json:"frames_written"`
	FramesBuffered  int           `json:"frames_buffered"`
	StartedAt       time.Time     `json:"started_at"`
	SealedAt        time.Time     `json:"sealed_at,omitempty"`
	SealReason      string        `json:"seal_reason,omitempty"`
}

// FileVerification summarizes one integrity pass over a recording file:
// every frame record is replayed and checked against its stored CRC32 while
// a whole-file checksum is accumulated.
type FileVerification struct {
	Frames int    `json:"frames"`
	Bytes  int64  `json:"bytes"`
	CRC32  uint32 `json:"crc32"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// DrainProgress is a point-in-time snapshot of how much of a segment's
// buffered tail has reached the recording file.
type DrainProgress struct {
	SegmentID      string        `json:"segment_id"`
	Status         SegmentStatus `json:"status"`
	FramesWritten  int           `json:"frames_written"`
	FramesBuffered int           `json:"frames_buffered"`
	LastDrained    int           `json:"last_drained"`
	FileBytes      int64         `json:"file_bytes"`
	FileCRC32      uint32        `json:"file_crc32"`
	Verified       bool          `json:"verified"`
	VerifyError    string        `json:"verify_error,omitempty"`
	SealReady      bool          `json:"seal_ready"`
}

// DrainOutcome reports what a single Drain call accomplished. Drained counts
// only the frames this call appended; previously committed frames are never
// rewritten, so a retry after cancellation resumes at the boundary.
type DrainOutcome struct {
	Drained  int           `json:"drained"`
	Canceled bool          `json:"canceled"`
	Progress DrainProgress `json:"progress"`
}

// SealPreview describes whether Seal would succeed right now, without
// changing any state.
type SealPreview struct {
	Segment  Segment       `json:"segment"`
	Progress DrainProgress `json:"progress"`
	Ready    bool          `json:"ready"`
	Blockers []string      `json:"blockers,omitempty"`
}

type SealResult struct {
	Segment      Segment          `json:"segment"`
	Complete     bool             `json:"complete"`
	Verification FileVerification `json:"verification"`
	Error        string           `json:"error,omitempty"`
}
