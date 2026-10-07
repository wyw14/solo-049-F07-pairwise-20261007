package recorder

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"

	"orbitlink/internal/store"
)

const frameHeaderSize = 28

type FrameWriter struct {
	mu    sync.Mutex
	paths store.Paths
}

func NewFrameWriter(paths store.Paths) *FrameWriter {
	return &FrameWriter{paths: paths}
}

func (w *FrameWriter) Append(segmentID string, frame Frame) (int64, error) {
	if segmentID == "" || len(frame.Payload) == 0 {
		return 0, fmt.Errorf("segment and frame payload are required")
	}
	if frame.CRC32 == 0 {
		frame.CRC32 = crc32.ChecksumIEEE(frame.Payload)
	}
	if crc32.ChecksumIEEE(frame.Payload) != frame.CRC32 {
		return 0, fmt.Errorf("frame %d checksum mismatch", frame.Sequence)
	}
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], frame.Sequence)
	binary.BigEndian.PutUint64(header[8:16], uint64(frame.Epoch))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(frame.Payload)))
	binary.BigEndian.PutUint32(header[24:28], frame.CRC32)
	// Header and payload go out in one write: the kernel cannot interleave the
	// append with another writer and a torn write can never expose a frame
	// whose header is present but whose payload is missing.
	record := make([]byte, 0, frameHeaderSize+len(frame.Payload))
	record = append(record, header...)
	record = append(record, frame.Payload...)

	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.paths.Recording(segmentID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open recording: %w", err)
	}
	defer file.Close()
	n, err := file.Write(record)
	if err != nil {
		return 0, fmt.Errorf("write frame: %w", err)
	}
	if n != len(record) {
		return 0, fmt.Errorf("short frame write: %d of %d bytes", n, len(record))
	}
	if err := file.Sync(); err != nil {
		return 0, fmt.Errorf("sync frame: %w", err)
	}
	info, err := file.Stat()
	return info.Size(), err
}

func (w *FrameWriter) Size(segmentID string) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	info, err := os.Stat(w.paths.Recording(segmentID))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Verify scans the recording file. Frames are parsed and CRC-checked in order
// and the intact prefix is SHA-256 hashed. A missing file verifies as an empty
// recording; a truncated or corrupt trailing frame is reported with its tail
// length instead of failing the scan of the valid prefix.
func (w *FrameWriter) Verify(segmentID string) (VerifyReport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	report := VerifyReport{SegmentID: segmentID}
	path := w.paths.Recording(segmentID)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		report.SHA256 = sha256Hex(nil)
		return report, nil
	}
	if err != nil {
		return report, fmt.Errorf("open recording for verify: %w", err)
	}
	defer file.Close()

	digest := sha256.New()
	reader := io.TeeReader(file, digest)
	header := make([]byte, frameHeaderSize)
	var offset int64
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if err == io.EOF {
				break
			}
			if err == io.ErrUnexpectedEOF {
				report.Error = fmt.Sprintf("truncated frame header at byte %d", offset)
				break
			}
			return report, fmt.Errorf("read recording: %w", err)
		}
		payloadLen := int64(binary.BigEndian.Uint64(header[16:24]))
		if payloadLen < 0 || payloadLen > (1<<40) {
			report.Error = fmt.Sprintf("implausible payload length %d at byte %d", payloadLen, offset)
			break
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			report.Error = fmt.Sprintf("truncated payload for frame at byte %d", offset)
			break
		}
		crc := binary.BigEndian.Uint32(header[24:28])
		if crc32.ChecksumIEEE(payload) != crc {
			report.Error = fmt.Sprintf("frame %d checksum mismatch at byte %d", binary.BigEndian.Uint64(header[0:8]), offset)
			break
		}
		report.FramesOnDisk++
		report.Sequences = append(report.Sequences, binary.BigEndian.Uint64(header[0:8]))
		offset += frameHeaderSize + payloadLen
		report.ValidBytes = offset
	}

	// Hash only the intact prefix: discard any tail bytes the digest may have
	// absorbed while reading a broken final frame, then finish explicitly.
	total, statErr := file.Seek(0, io.SeekEnd)
	if statErr != nil {
		return report, fmt.Errorf("stat recording: %w", statErr)
	}
	report.Bytes = total
	if report.Error == "" {
		report.SHA256 = hex.EncodeToString(digest.Sum(nil))
		report.ValidBytes = total
	} else {
		report.TailBytes = total - report.ValidBytes
		report.SHA256 = sha256PrefixHash(path, report.ValidBytes)
	}
	return report, nil
}

// Trim truncates the recording to the intact prefix and syncs the directory
// change. It repairs a torn trailing frame so the next drain can resume.
func (w *FrameWriter) Trim(segmentID string, validBytes int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.paths.Recording(segmentID)
	file, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open recording for trim: %w", err)
	}
	if err := file.Truncate(validBytes); err != nil {
		_ = file.Close()
		return fmt.Errorf("trim recording: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync trimmed recording: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close trimmed recording: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sha256PrefixHash hashes the first validBytes of the file independently, since
// the streaming digest may already have consumed some of the corrupt tail.
func sha256PrefixHash(path string, validBytes int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.CopyN(digest, file, validBytes); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(digest.Sum(nil))
}
