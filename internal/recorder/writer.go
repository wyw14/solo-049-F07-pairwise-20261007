package recorder

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"

	"orbitlink/internal/store"
)

// frameHeaderSize is sequence + epoch + payload length + CRC32.
const frameHeaderSize = 28

// maxFramePayload bounds a single frame record so a corrupt length field
// cannot trigger an unbounded allocation during verification.
const maxFramePayload = 4 << 20

type FrameWriter struct {
	mu    sync.Mutex
	paths store.Paths
}

func NewFrameWriter(paths store.Paths) *FrameWriter {
	return &FrameWriter{paths: paths}
}

func (w *FrameWriter) Append(segmentID string, frame Frame) error {
	if segmentID == "" || len(frame.Payload) == 0 {
		return fmt.Errorf("segment and frame payload are required")
	}
	if frame.CRC32 == 0 {
		frame.CRC32 = crc32.ChecksumIEEE(frame.Payload)
	}
	if crc32.ChecksumIEEE(frame.Payload) != frame.CRC32 {
		return fmt.Errorf("frame %d checksum mismatch", frame.Sequence)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.paths.Recording(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], frame.Sequence)
	binary.BigEndian.PutUint64(header[8:16], uint64(frame.Epoch))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(frame.Payload)))
	binary.BigEndian.PutUint32(header[24:28], frame.CRC32)
	if _, err := writer.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := writer.Write(frame.Payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush frame: %w", err)
	}
	return file.Sync()
}

func (w *FrameWriter) Size(segmentID string) (int64, error) {
	info, err := os.Stat(w.paths.Recording(segmentID))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Verify replays a recording file, checking every frame record against its
// stored CRC32 and accumulating a whole-file checksum. A missing file is a
// valid empty recording; any truncation, corruption or checksum mismatch
// fails the verification.
func (w *FrameWriter) Verify(segmentID string) FileVerification {
	result := FileVerification{OK: true}
	w.mu.Lock()
	defer w.mu.Unlock()
	file, err := os.Open(w.paths.Recording(segmentID))
	if os.IsNotExist(err) {
		return result
	}
	if err != nil {
		return FileVerification{OK: false, Error: fmt.Sprintf("open recording: %v", err)}
	}
	defer file.Close()
	hasher := crc32.NewIEEE()
	reader := io.TeeReader(file, hasher)
	header := make([]byte, frameHeaderSize)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if err != io.EOF {
				result.OK = false
				result.Error = fmt.Sprintf("truncated frame header after %d frames", result.Frames)
			}
			break
		}
		result.Bytes += frameHeaderSize
		sequence := binary.BigEndian.Uint64(header[0:8])
		length := binary.BigEndian.Uint64(header[16:24])
		want := binary.BigEndian.Uint32(header[24:28])
		if length > maxFramePayload {
			result.OK = false
			result.Error = fmt.Sprintf("frame %d declares %d payload bytes", sequence, length)
			break
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			result.OK = false
			result.Error = fmt.Sprintf("truncated payload for frame %d", sequence)
			break
		}
		result.Bytes += int64(length)
		if crc32.ChecksumIEEE(payload) != want {
			result.OK = false
			result.Error = fmt.Sprintf("frame %d checksum mismatch", sequence)
			break
		}
		result.Frames++
	}
	result.CRC32 = hasher.Sum32()
	return result
}
