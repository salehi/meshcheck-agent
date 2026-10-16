// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
	"github.com/salehi/meshcheck-agent/pkg/checkspec"
	"github.com/salehi/meshcheck-agent/pkg/resultsig"
	"github.com/salehi/meshcheck-agent/pkg/slot"
)

// Standing assignments (doc/protocols/agent-protocol.md §Standing
// assignments): the platform says "run this check every interval, at this
// phase" once, and the agent fires every slot itself, on the platform's
// clock, and streams the signed results back in batches. Nothing is
// dispatched per run, so there is no per-run message, no drift, and no burst
// of Tasks landing at once.
//
// Assignments outlive a connection: a brief disconnect does not stop them,
// and their results wait in the outbox until a connection acknowledges them.
// Each new connection starts with a full AssignmentSet that corrects
// anything that changed meanwhile.

// Assignment tuning.
const (
	// assignmentProbesInFlight bounds assignment probes running at once,
	// separately from the per-Task ceiling. With phases spread across the
	// interval a Node rarely has more than one running; a slot that finds
	// every slot busy is skipped (the platform reads it as no response).
	assignmentProbesInFlight = 8

	// batchFlushEvery and batchMax decide when queued results are sent: once
	// a second, or as soon as this many are waiting.
	batchFlushEvery = time.Second
	batchMax        = 100

	// resendAfter is how long a sent batch waits for its ack before it is
	// sent again.
	resendAfter = 10 * time.Second

	// resultMaxAge drops results the platform would no longer accept: it
	// closes a slot shortly after it ends.
	resultMaxAge = 5 * time.Minute

	// outboxMax bounds queued results during a long disconnect; the oldest
	// are dropped first.
	outboxMax = 10_000
)

// assigner owns the agent's standing assignments and its result outbox.
type assigner struct {
	c   *Client
	log *slog.Logger

	// offsetMs is the platform clock minus the local clock, measured at each
	// handshake.
	offsetMs atomic.Int64
	slots    chan struct{} // bounds assignment probes in flight

	mu      sync.Mutex
	ctx     context.Context // the process lifetime; assignments run under it
	running map[string]*runningAssignment
	version int64

	outMu    sync.Mutex
	queued   []*agentpb.SlotResult
	inflight map[string]*sentBatch
}

type runningAssignment struct {
	a      *agentpb.Assignment
	cancel context.CancelFunc
}

type sentBatch struct {
	results []*agentpb.SlotResult
	sentAt  time.Time
}

func newAssigner(c *Client) *assigner {
	return &assigner{
		c: c, log: c.log,
		slots:    make(chan struct{}, assignmentProbesInFlight),
		running:  map[string]*runningAssignment{},
		inflight: map[string]*sentBatch{},
	}
}

// start binds the assigner to the process lifetime. It is called on every
// connection; only the first call takes effect.
func (s *assigner) start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		s.ctx = ctx
	}
}

// setOffset records the platform clock's offset, from ServerHello's send
// time. The one-way network delay is ignored: results carry their slot index,
// so a few tens of milliseconds only move when the probe fires, not which
// slot it belongs to.
func (s *assigner) setOffset(platformMs, localMs int64) {
	s.offsetMs.Store(platformMs - localMs)
}

// platformNowMs is now on the platform's clock.
func (s *assigner) platformNowMs() int64 {
	return time.Now().UnixMilli() + s.offsetMs.Load()
}

// apply installs an AssignmentSet: a full set replaces every assignment, a
// delta adds, changes, and removes some. An assignment the agent cannot run
// (an unknown check type, invalid parameters) is skipped and logged.
func (s *assigner) apply(set *agentpb.AssignmentSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return
	}
	s.version = set.GetVersion()

	keep := map[string]bool{}
	for _, a := range set.GetUpserts() {
		keep[a.GetAssignmentId()] = true
		if cur, ok := s.running[a.GetAssignmentId()]; ok {
			if proto.Equal(cur.a, a) {
				continue // unchanged: keep firing on the same slots
			}
			cur.cancel()
			delete(s.running, a.GetAssignmentId())
		}
		if !slices.Contains(s.c.checkTypes, a.GetCheckType()) {
			s.log.Warn("assignment for a check type this agent cannot run",
				"assignment_id", a.GetAssignmentId(), "check_type", a.GetCheckType())
			continue
		}
		if err := checkspec.Validate(a.GetCheckType(), a.GetParameters()); err != nil {
			s.log.Warn("assignment with invalid parameters",
				"assignment_id", a.GetAssignmentId(), "error", err)
			continue
		}
		ctx, cancel := context.WithCancel(s.ctx)
		s.running[a.GetAssignmentId()] = &runningAssignment{a: a, cancel: cancel}
		go s.fire(ctx, a)
	}
	stop := set.GetRemoves()
	if set.GetFull() {
		stop = nil
		for id := range s.running {
			if !keep[id] {
				stop = append(stop, id)
			}
		}
	}
	for _, id := range stop {
		if cur, ok := s.running[id]; ok {
			cur.cancel()
			delete(s.running, id)
		}
	}
	s.log.Info("assignments updated", "version", s.version, "full", set.GetFull(),
		"running", len(s.running))
}

// fire probes an assignment at the start of every slot until cancelled. The
// next slot is computed from the platform clock each time — never "now plus
// the interval" — so a late wake-up or a slow probe cannot make it drift.
func (s *assigner) fire(ctx context.Context, a *agentpb.Assignment) {
	iv, ph := a.GetIntervalSeconds(), a.GetPhaseMs()
	for {
		now := s.platformNowMs()
		k := slot.Of(now, iv, ph) + 1
		wait := time.Duration(slot.Start(k, iv, ph)-now) * time.Millisecond
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		go s.probe(ctx, a, k)
	}
}

// probe runs one slot of an assignment and queues its signed result.
func (s *assigner) probe(ctx context.Context, a *agentpb.Assignment, k int64) {
	select {
	case s.slots <- struct{}{}:
	default:
		s.log.Warn("assignment slot skipped: too many probes in flight",
			"assignment_id", a.GetAssignmentId(), "slot", k)
		return
	}
	defer func() { <-s.slots }()

	timeout := time.Duration(a.GetTimeoutMs()) * time.Millisecond
	if iv := time.Duration(a.GetIntervalSeconds()) * time.Second; timeout <= 0 || timeout > iv {
		timeout = iv
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	outcome, measurements := runCheck(pctx, a.GetCheckType(), a.GetTarget(), a.GetParameters())
	if ctx.Err() != nil {
		return // the assignment was withdrawn mid-probe
	}
	r := &agentpb.SlotResult{
		AssignmentId: a.GetAssignmentId(),
		Slot:         k,
		Outcome:      outcome,
		Measurements: measurements,
		StartedAt:    started.UnixMilli(),
		CompletedAt:  time.Now().UnixMilli(),
	}
	r.Signature = resultsig.SignSlot(s.c.priv, r)
	s.enqueue(r)
}

// --- the result outbox ---

func (s *assigner) enqueue(r *agentpb.SlotResult) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.queued = append(s.queued, r)
	if over := len(s.queued) - outboxMax; over > 0 {
		s.queued = s.queued[over:]
	}
}

// reconnected requeues every batch the previous connection never had
// acknowledged, so it is sent again on this one.
func (s *assigner) reconnected() {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	for id, b := range s.inflight {
		s.queued = append(b.results, s.queued...)
		delete(s.inflight, id)
	}
}

// acked drops a batch the platform has taken.
func (s *assigner) acked(ack *agentpb.SlotResultBatchAck) {
	s.outMu.Lock()
	delete(s.inflight, ack.GetBatchId())
	s.outMu.Unlock()
	if ack.GetRefused() > 0 {
		s.log.Warn("platform refused slot results", "batch_id", ack.GetBatchId(),
			"refused", ack.GetRefused(), "accepted", ack.GetAccepted())
	}
}

// flushLoop sends queued results in batches over one connection until it
// ends, and resends batches whose ack is overdue.
func (s *assigner) flushLoop(ctx context.Context) {
	t := time.NewTicker(batchFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.flush()
		}
	}
}

func (s *assigner) flush() {
	s.outMu.Lock()
	now := time.Now()
	for id, b := range s.inflight {
		if now.Sub(b.sentAt) > resendAfter {
			s.queued = append(b.results, s.queued...)
			delete(s.inflight, id)
		}
	}
	s.queued = slices.DeleteFunc(s.queued, func(r *agentpb.SlotResult) bool {
		return now.Sub(time.UnixMilli(r.GetCompletedAt())) > resultMaxAge
	})
	var batches []*agentpb.SlotResultBatch
	for len(s.queued) > 0 {
		n := min(batchMax, len(s.queued))
		b := &agentpb.SlotResultBatch{BatchId: ulid.Make().String(), Results: s.queued[:n:n]}
		s.queued = s.queued[n:]
		s.inflight[b.BatchId] = &sentBatch{results: b.Results, sentAt: now}
		batches = append(batches, b)
	}
	s.outMu.Unlock()
	for _, b := range batches {
		s.c.trySend(wrap(b))
	}
}
