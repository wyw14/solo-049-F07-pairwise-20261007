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
	// FileBytes is the durable byte offset of the recording file and lets the
	// drain reconcile committed frames after an interrupted write.
	FileBytes int64 `json:"file_bytes"`
	// ChecksumSHA256 attests the sealed recording file contents. It is only
	// populated after verification passes at seal time.
	ChecksumSHA256 string `json:"checksum_sha256,omitempty"`
	// VerifyError records the last failed file verification; it is cleared on
	// the next successful verification.
	VerifyError string    `json:"verify_error,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	SealedAt    time.Time `json:"sealed_at,omitempty"`
	SealReason  string    `json:"seal_reason,omitempty"`
}

// DrainResult reports a drain pass. Written frames are committed to the
// recording file and removed from the buffer; Remaining frames stayed buffered.
// Complete is true only when the buffer was fully emptied and the file passed
// verification.
type DrainResult struct {
	SegmentID      string        `json:"segment_id"`
	Status         SegmentStatus `json:"status"`
	Total          int           `json:"total_frames"`
	WrittenThisRun int           `json:"written_this_run"`
	FramesWritten  int           `json:"frames_written"`
	Remaining      int           `json:"frames_remaining"`
	BytesOnDisk    int64         `json:"bytes_on_disk"`
	Complete       bool          `json:"complete"`
	ChecksumSHA256 string        `json:"checksum_sha256,omitempty"`
	Canceled       bool          `json:"canceled,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// SealPreview describes whether a segment is ready to seal without changing
// any state: remaining buffered frames and the recording file verification.
type SealPreview struct {
	SegmentID      string        `json:"segment_id"`
	Status         SegmentStatus `json:"status"`
	FramesWritten  int           `json:"frames_written"`
	Remaining      int           `json:"frames_buffered"`
	BytesOnDisk    int64         `json:"bytes_on_disk"`
	Verified       bool          `json:"verified"`
	ChecksumSHA256 string        `json:"checksum_sha256,omitempty"`
	Ready          bool          `json:"ready"`
	Blockers       []string      `json:"blockers,omitempty"`
	VerifyError    string        `json:"verify_error,omitempty"`
}

type SealResult struct {
	Segment  Segment `json:"segment"`
	Complete bool    `json:"complete"`
	Error    string  `json:"error,omitempty"`
}

// VerifyReport is the result of scanning a recording file: every readable
// frame is CRC-checked and the complete file bytes are hashed.
type VerifyReport struct {
	SegmentID    string
	FramesOnDisk int
	Bytes        int64
	SHA256       string
	// Sequences lists the frame sequence numbers of the intact frames in file
	// order; it identifies exactly which buffered frames are already durable.
	Sequences []uint64
	// ValidBytes is the length of the intact frame prefix; a short or corrupt
	// trailing frame leaves a tail beyond this offset.
	ValidBytes int64
	TailBytes  int64
	Error      string
}

// Healthy reports whether the whole file is a sequence of intact, CRC-valid
// frames with no trailing garbage.
func (r VerifyReport) Healthy() bool {
	return r.Error == "" && r.TailBytes == 0
}
