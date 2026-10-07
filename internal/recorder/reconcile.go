package recorder

import "fmt"

// reconcile matches the in-memory buffer against the durable file sequences.
//
// It returns how many frames at the head of the buffer are already durable
// (matched) and how many intact file frames precede the buffer entirely
// (beforeBuffer — frames written by a previous process whose in-memory buffer
// was lost on restart). Sequences are monotonic per segment, so alignment is
// found by locating the first buffered sequence in the file. A sequence that
// conflicts with the aligned file prefix is a divergence, not a duplicate to
// rewrite.
func reconcile(buffer []Frame, fileSequences []uint64) (matched, beforeBuffer int, divergence string) {
	if len(buffer) == 0 {
		return 0, len(fileSequences), ""
	}
	first := buffer[0].Sequence
	start := -1
	for index := len(fileSequences) - 1; index >= 0; index-- {
		if fileSequences[index] == first {
			start = index
			break
		}
	}
	if start < 0 {
		// Nothing buffered is on disk yet; all file frames predate the buffer.
		return 0, len(fileSequences), ""
	}
	for matched = 0; matched < len(buffer); matched++ {
		filePos := start + matched
		if filePos >= len(fileSequences) {
			break
		}
		if fileSequences[filePos] != buffer[matched].Sequence {
			return matched, start, fmt.Sprintf("file frame %d does not match buffered frame %d at position %d", fileSequences[filePos], buffer[matched].Sequence, matched)
		}
	}
	return matched, start, ""
}

// matchedPrefix is the common in-process case where file frames form a prefix
// of the buffer; it discards the beforeBuffer count.
func matchedPrefix(buffer []Frame, fileSequences []uint64) (int, string) {
	matched, _, divergence := reconcile(buffer, fileSequences)
	return matched, divergence
}
