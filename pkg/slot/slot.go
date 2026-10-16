// SPDX-License-Identifier: Apache-2.0

// Package slot is the time arithmetic of standing assignments, shared by the
// agent (which fires each slot) and the platform (which groups results by
// slot), so the two can never disagree about which slot an instant is in.
//
// An assignment with interval I (seconds) and phase P (milliseconds, 0 ≤ P <
// I·1000) divides time into slots: slot k starts at unix millisecond
// k·I·1000 + P. Every Node running the assignment fires slot k at the same
// instant of the platform's clock, and a result names its slot, so grouping
// never depends on the Node's own wall clock. See
// doc/protocols/agent-protocol.md §Standing assignments.
package slot

import (
	"hash/fnv"
	"time"
)

// Of returns the slot an instant (unix milliseconds) falls in: the k with
// Start(k) ≤ t < Start(k+1). It is defined for any t, including before 1970.
func Of(tMs int64, intervalSeconds, phaseMs int32) int64 {
	iv := intervalMs(intervalSeconds)
	d := tMs - int64(phaseMs)
	k := d / iv
	if d%iv < 0 { // floor division for negative d
		k--
	}
	return k
}

// Start returns the unix millisecond at which slot k begins.
func Start(k int64, intervalSeconds, phaseMs int32) int64 {
	return k*intervalMs(intervalSeconds) + int64(phaseMs)
}

// StartTime is Start as a time.Time.
func StartTime(k int64, intervalSeconds, phaseMs int32) time.Time {
	return time.UnixMilli(Start(k, intervalSeconds, phaseMs))
}

// Phase spreads assignments over their interval: a stable offset in
// [0, interval) derived from the assignment's ID, so Monitors that share an
// interval do not all fire on the same instant.
func Phase(assignmentID string, intervalSeconds int32) int32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(assignmentID))
	return int32(h.Sum64() % uint64(intervalMs(intervalSeconds)))
}

// intervalMs is the interval in milliseconds, at least 1 ms so a malformed
// assignment can never divide by zero.
func intervalMs(intervalSeconds int32) int64 {
	if intervalSeconds < 1 {
		return 1000
	}
	return int64(intervalSeconds) * 1000
}
