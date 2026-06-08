// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
	"github.com/salehi/meshcheck-agent/pkg/checkspec"
	"github.com/salehi/meshcheck-agent/pkg/resultsig"
)

// agentSubprotocol must match the gateway's. The agent version it advertises is
// build-time-injected; see version.go.
const agentSubprotocol = "meshcheck.agent.v1"

// Connection defaults applied when ServerHello omits a value.
const (
	defaultHeartbeat   = 30 * time.Second
	defaultMaxInflight = 5
	sendBuffer         = 64
)

// protocolViolationCooldown is the minimum wait after a protocol-violation
// shutdown before reconnecting (see agent-protocol.md §Errors).
const protocolViolationCooldown = 60 * time.Second

// connectionClassEnum maps the agent's configured connection class onto the
// protocol enum.
var connectionClassEnum = map[string]agentpb.ConnectionClass{
	"vps":                  agentpb.ConnectionClass_CONNECTION_CLASS_VPS,
	"residential_wired":    agentpb.ConnectionClass_CONNECTION_CLASS_RESIDENTIAL_WIRED,
	"residential_wireless": agentpb.ConnectionClass_CONNECTION_CLASS_RESIDENTIAL_WIRELESS,
	"office":               agentpb.ConnectionClass_CONNECTION_CLASS_OFFICE,
	"mobile":               agentpb.ConnectionClass_CONNECTION_CLASS_MOBILE,
	"unknown":              agentpb.ConnectionClass_CONNECTION_CLASS_UNKNOWN,
}

// Client is the agent's protocol client: it owns one connection at a time and
// is driven by main's reconnect loop.
type Client struct {
	cfg        Config
	priv       ed25519.PrivateKey
	log        *slog.Logger
	checkTypes []string // capabilities advertised to the platform

	ws   *websocket.Conn
	send chan *agentpb.Envelope
	sem  chan struct{} // bounds concurrent task execution

	// Self-update bookkeeping (see update.go). attemptedVersion guards against
	// acting on repeated UpdateAvailable offers for the same target within this
	// process's lifetime.
	updateMu         sync.Mutex
	updateActive     bool
	attemptedVersion string
}

// newClient builds a Client and probes which check types it can run.
func newClient(cfg Config, priv ed25519.PrivateKey, log *slog.Logger) *Client {
	types := []string{checkspec.TypeTCP, checkspec.TypeHTTP, checkspec.TypeDNS, checkspec.TypeTLS, checkspec.TypeSMTP}
	if icmpAvailable() {
		types = append([]string{checkspec.TypePing}, types...)
	} else {
		log.Warn("ICMP unavailable; this agent will not advertise the ping capability")
	}
	return &Client{cfg: cfg, priv: priv, log: log, checkTypes: types}
}

// Run connects once and serves the connection until it ends. It returns
// whether a session was actually established (so the caller can reset its
// backoff) and the delay to wait before reconnecting.
func (c *Client) Run(ctx context.Context) (connected bool, reconnectDelay time.Duration) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	header.Set("X-Agent-Version", agentVersion)
	header.Set("X-Agent-Platform", runtime.GOOS+"/"+runtime.GOARCH)

	ws, _, err := websocket.Dial(dialCtx, c.cfg.GatewayURL, &websocket.DialOptions{
		Subprotocols: []string{agentSubprotocol},
		HTTPHeader:   header,
	})
	cancel()
	if err != nil {
		c.log.Warn("connection failed", "error", err)
		return false, 0
	}
	c.ws = ws
	defer ws.CloseNow()

	heartbeat, maxInflight, err := c.handshake(ctx)
	if err != nil {
		c.log.Warn("handshake failed", "error", err)
		return false, 0
	}
	// The effective in-flight ceiling is the smaller of what the platform
	// advertised and what this agent will allow itself — a contributor on a
	// modest machine caps its own load regardless of the platform's limit.
	inflight := min(maxInflight, c.cfg.MaxConcurrentTasks)
	c.send = make(chan *agentpb.Envelope, sendBuffer)
	c.sem = make(chan struct{}, inflight)

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go c.writeLoop(runCtx)
	go c.heartbeatLoop(runCtx, heartbeat)

	c.log.Info("connected", "heartbeat_seconds", heartbeat/time.Second,
		"max_inflight", inflight, "platform_limit", maxInflight)
	return true, c.readLoop(runCtx)
}

// handshake waits for ServerHello and replies with ClientHello, returning the
// negotiated heartbeat cadence and in-flight ceiling.
func (c *Client) handshake(ctx context.Context) (heartbeat time.Duration, maxInflight int, err error) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	env, err := readEnvelope(hctx, c.ws)
	if err != nil {
		return 0, 0, err
	}
	hello := env.GetServerHello()
	if hello == nil {
		return 0, 0, errors.New("first message was not a ServerHello")
	}

	heartbeat = time.Duration(hello.GetHeartbeatIntervalSeconds()) * time.Second
	if heartbeat <= 0 {
		heartbeat = defaultHeartbeat
	}
	maxInflight = int(hello.GetMaxConcurrentTasks())
	if maxInflight <= 0 {
		maxInflight = defaultMaxInflight
	}

	if err := writeEnvelope(hctx, c.ws, c.clientHello()); err != nil {
		return 0, 0, err
	}
	return heartbeat, maxInflight, nil
}

// clientHello builds the agent's ClientHello, declaring its capabilities and
// registering its Result-signing public key.
func (c *Client) clientHello() *agentpb.Envelope {
	connClass, ok := connectionClassEnum[c.cfg.ConnectionClass]
	if !ok {
		connClass = agentpb.ConnectionClass_CONNECTION_CLASS_UNKNOWN
	}
	return wrap(&agentpb.ClientHello{
		AgentVersion: agentVersion,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		Capabilities: &agentpb.Capabilities{
			SupportedCheckTypes: c.checkTypes,
			CanSendIcmp:         slices.Contains(c.checkTypes, checkspec.TypePing),
			ConnectionClass:     connClass,
			Name:                c.cfg.Name,
			Geo: &agentpb.GeoLocation{
				CountryCode: c.cfg.Country,
				City:        c.cfg.City,
			},
		},
		Ed25519Pubkey: c.priv.Public().(ed25519.PublicKey),
	})
}

// readLoop processes inbound messages until the connection ends, returning the
// reconnect delay.
func (c *Client) readLoop(ctx context.Context) time.Duration {
	for {
		env, err := readEnvelope(ctx, c.ws)
		if err != nil {
			c.log.Info("disconnected", "error", err)
			return 0
		}
		switch body := env.Body.(type) {
		case *agentpb.Envelope_Task:
			go c.executeTask(ctx, body.Task)
		case *agentpb.Envelope_TaskCancel:
			c.log.Info("task cancelled by platform", "task_id", body.TaskCancel.GetTaskId())
		case *agentpb.Envelope_UpdateAvailable:
			go c.handleUpdate(ctx, body.UpdateAvailable)
		case *agentpb.Envelope_Shutdown:
			reason := body.Shutdown.GetReason()
			c.log.Info("shutdown requested", "reason", reason.String())
			if reason == agentpb.ShutdownReason_SHUTDOWN_REASON_PROTOCOL_VIOLATION {
				return protocolViolationCooldown
			}
			return 5 * time.Second
		case *agentpb.Envelope_FlowControl:
			c.log.Info("flow control", "max_inflight", body.FlowControl.GetMaxInflightTasks())
		case *agentpb.Envelope_ResultAck:
			c.log.Debug("result acknowledged",
				"task_id", body.ResultAck.GetTaskId(), "persisted", body.ResultAck.GetPersisted())
		case *agentpb.Envelope_Error:
			c.log.Warn("platform error", "code", body.Error.GetCode(), "message", body.Error.GetMessage())
		default:
			c.log.Warn("unexpected message type")
		}
	}
}

// executeTask validates, runs, signs, and submits one Task.
func (c *Client) executeTask(ctx context.Context, task *agentpb.TaskAssignment) {
	if !slices.Contains(c.checkTypes, task.GetCheckType()) {
		c.trySend(taskAck(task.GetTaskId(), agentpb.TaskAckStatus_TASK_ACK_REJECTED_INCAPABLE))
		return
	}
	if err := checkspec.Validate(task.GetCheckType(), task.GetParameters()); err != nil {
		c.log.Warn("rejecting task with invalid parameters", "task_id", task.GetTaskId(), "error", err)
		c.trySend(taskAck(task.GetTaskId(), agentpb.TaskAckStatus_TASK_ACK_REJECTED_INVALID))
		return
	}

	// Respect the in-flight ceiling rather than overcommitting the host.
	select {
	case c.sem <- struct{}{}:
	default:
		c.trySend(taskAck(task.GetTaskId(), agentpb.TaskAckStatus_TASK_ACK_REJECTED_OVERLOAD))
		return
	}
	defer func() { <-c.sem }()

	c.trySend(taskAck(task.GetTaskId(), agentpb.TaskAckStatus_TASK_ACK_ACCEPTED))

	taskCtx := ctx
	if dl := task.GetDeadline(); dl > 0 {
		var cancel context.CancelFunc
		taskCtx, cancel = context.WithDeadline(ctx, time.UnixMilli(dl))
		defer cancel()
	}

	started := time.Now()
	outcome, measurements := runCheck(taskCtx, task.GetCheckType(), task.GetTarget(), task.GetParameters())
	completed := time.Now()

	result := &agentpb.ResultSubmit{
		TaskId:       task.GetTaskId(),
		CheckId:      task.GetCheckId(),
		Outcome:      outcome,
		Measurements: measurements,
		StartedAt:    started.UnixMilli(),
		CompletedAt:  completed.UnixMilli(),
	}
	result.Signature = resultsig.Sign(c.priv, result)

	c.log.Info("check complete",
		"task_id", task.GetTaskId(), "check_type", task.GetCheckType(), "outcome", outcome.String())
	c.trySend(wrap(result))
}

// heartbeatLoop sends a Heartbeat at the cadence ServerHello requested.
func (c *Client) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.trySend(wrap(&agentpb.Heartbeat{CurrentLoad: int32(len(c.sem))}))
		}
	}
}

// writeLoop drains the outbound queue onto the WebSocket.
func (c *Client) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-c.send:
			if err := writeEnvelope(ctx, c.ws, env); err != nil {
				return
			}
		}
	}
}

// trySend enqueues an outbound message, dropping it if the queue is full.
func (c *Client) trySend(env *agentpb.Envelope) {
	select {
	case c.send <- env:
	default:
		c.log.Warn("send buffer full; dropping outbound message")
	}
}

// --- envelope helpers ---

// wrap places a message body in an Envelope with a fresh ID and timestamp.
func wrap(body any) *agentpb.Envelope {
	env := &agentpb.Envelope{MessageId: ulid.Make().String(), SentAt: time.Now().UnixMilli()}
	switch m := body.(type) {
	case *agentpb.ClientHello:
		env.Body = &agentpb.Envelope_ClientHello{ClientHello: m}
	case *agentpb.Heartbeat:
		env.Body = &agentpb.Envelope_Heartbeat{Heartbeat: m}
	case *agentpb.TaskAck:
		env.Body = &agentpb.Envelope_TaskAck{TaskAck: m}
	case *agentpb.ResultSubmit:
		env.Body = &agentpb.Envelope_Result{Result: m}
	default:
		panic("agent: wrap given an unsupported body type")
	}
	return env
}

// taskAck builds a TaskAck envelope.
func taskAck(taskID string, status agentpb.TaskAckStatus) *agentpb.Envelope {
	return wrap(&agentpb.TaskAck{TaskId: taskID, Status: status})
}

// writeEnvelope marshals and writes one Envelope as a single binary frame.
func writeEnvelope(ctx context.Context, ws *websocket.Conn, env *agentpb.Envelope) error {
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(ctx, websocket.MessageBinary, data)
}

// readEnvelope reads one binary frame and unmarshals it.
func readEnvelope(ctx context.Context, ws *websocket.Conn) (*agentpb.Envelope, error) {
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("expected a binary frame")
	}
	var env agentpb.Envelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
