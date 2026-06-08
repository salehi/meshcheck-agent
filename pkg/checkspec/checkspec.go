// SPDX-License-Identifier: Apache-2.0

// Package checkspec defines the per-Check-Type parameter and measurement
// shapes shared by the platform and the Node agent.
//
// On the wire these travel as JSON inside the protocol's `parameters` and
// `measurements` byte fields (see doc/protocols/agent-protocol.md); in the
// database they are the `checks.parameters` and `results.measurements` jsonb
// columns (doc/schema/schema.md). Keeping both sides on these types is what
// keeps the two representations in agreement.
package checkspec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Check types the platform can dispatch. Phase 2 shipped ping/tcp/http;
// Phase 7 adds the specialized types incrementally.
const (
	TypePing = "ping"
	TypeTCP  = "tcp"
	TypeHTTP = "http"
	TypeDNS  = "dns"
	TypeTLS  = "tls"
	TypeSMTP = "smtp"
)

// Supported reports whether a check type can be dispatched.
func Supported(checkType string) bool {
	switch checkType {
	case TypePing, TypeTCP, TypeHTTP, TypeDNS, TypeTLS, TypeSMTP:
		return true
	default:
		return false
	}
}

// --- Parameters: produced by the Requester, consumed by the agent ---

// PingParams configures an ICMP echo Check.
type PingParams struct {
	Count          int `json:"count"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

// TCPParams configures a TCP connect Check.
type TCPParams struct {
	Port           int `json:"port"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

// HTTPParams configures an HTTP/HTTPS Check.
type HTTPParams struct {
	Method         string `json:"method"`
	ExpectedStatus int    `json:"expected_status"` // 0 means "any 2xx"
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// DNSParams configures a DNS resolution Check.
type DNSParams struct {
	RecordType     string `json:"record_type"` // A, AAAA, CNAME, MX, TXT, NS
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// TLSParams configures a TLS handshake / certificate Check.
type TLSParams struct {
	Port           int `json:"port"` // defaults to 443
	TimeoutSeconds int `json:"timeout_seconds"`
}

// SMTPParams configures an SMTP service Check.
type SMTPParams struct {
	Port           int `json:"port"` // defaults to 25
	TimeoutSeconds int `json:"timeout_seconds"`
}

// --- Measurements: produced by the agent, consumed by aggregation ---

// PingMeasurements is the result payload of a ping Check. The ping Check is in
// fact a traceroute: the Node probes the target with TTL-limited ICMP echoes,
// recording the route in Hops, and the top-level packet/RTT statistics describe
// the final hop (the target itself). ResolvedIPs records the address(es) the
// Node actually resolved the target to before probing — for a hostname target
// this exposes per-Node GeoDNS divergence on the result page; for a literal-IP
// target it simply echoes the target.
type PingMeasurements struct {
	PacketsSent   int      `json:"packets_sent"`
	PacketsRecv   int      `json:"packets_recv"`
	PacketLossPct float64  `json:"packet_loss_pct"`
	RTTMinMs      float64  `json:"rtt_min_ms"`
	RTTAvgMs      float64  `json:"rtt_avg_ms"`
	RTTMaxMs      float64  `json:"rtt_max_ms"`
	RTTStdDevMs   float64  `json:"rtt_stddev_ms"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"`
	// Hops is the measured route to the target, one entry per TTL in order. A
	// hop with an empty IP is one that did not answer within the probe window.
	// The last hop reaching the target is the target itself.
	Hops []Hop `json:"hops,omitempty"`
}

// Hop is one stop on the traceroute to a ping Check's target. RTTMs holds the
// round-trip time of each probe sent at this TTL (a probe that timed out
// contributes no entry); an empty IP means no router answered at this distance.
type Hop struct {
	TTL    int       `json:"ttl"`
	IP     string    `json:"ip,omitempty"`
	RTTMs  []float64 `json:"rtt_ms,omitempty"`
	Target bool      `json:"target,omitempty"` // true once the probe reached the target
}

// TCPMeasurements is the result payload of a tcp Check.
type TCPMeasurements struct {
	Connected bool    `json:"connected"`
	LatencyMs float64 `json:"latency_ms"`
}

// HTTPMeasurements is the result payload of an http Check. ResolvedIPs records
// the address(es) the Node resolved the host to, exposing per-Node GeoDNS
// divergence on the result page.
type HTTPMeasurements struct {
	StatusCode  int      `json:"status_code"`
	LatencyMs   float64  `json:"latency_ms"`
	TTFBMs      float64  `json:"ttfb_ms"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}

// DNSMeasurements is the result payload of a dns Check.
type DNSMeasurements struct {
	Resolved    bool     `json:"resolved"`
	RecordType  string   `json:"record_type"`
	RecordCount int      `json:"record_count"`
	Records     []string `json:"records"`
	LatencyMs   float64  `json:"latency_ms"`
}

// TLSMeasurements is the result payload of a tls Check. The certificate
// fields are reported even when the certificate is invalid or expired, so
// expiry alerting still has the data it needs.
type TLSMeasurements struct {
	HandshakeOK       bool    `json:"handshake_ok"`
	LatencyMs         float64 `json:"latency_ms"`
	TLSVersion        string  `json:"tls_version"`
	CipherSuite       string  `json:"cipher_suite"`
	CertSubject       string  `json:"cert_subject"`
	CertIssuer        string  `json:"cert_issuer"`
	CertExpiresAt     string  `json:"cert_expires_at"` // RFC 3339
	CertDaysRemaining int     `json:"cert_days_remaining"`
	CertValid         bool    `json:"cert_valid"` // chain trusted, hostname matches, not expired
}

// SMTPMeasurements is the result payload of an smtp Check.
type SMTPMeasurements struct {
	Connected          bool    `json:"connected"`
	LatencyMs          float64 `json:"latency_ms"`
	BannerCode         int     `json:"banner_code"`         // the greeting reply code; 220 on success
	Banner             string  `json:"banner"`              // the greeting's first line
	EHLOOK             bool    `json:"ehlo_ok"`             // the server accepted EHLO
	STARTTLSAdvertised bool    `json:"starttls_advertised"` // STARTTLS appeared among the EHLO extensions
}

// defaulting and validation bounds.
const (
	defaultPingCount   = 4
	maxPingCount       = 20
	defaultTimeoutSecs = 10
	maxTimeoutSecs     = 60
)

// ParsePingParams decodes and defaults ping parameters, rejecting nonsensical
// values so a bad Check fails at submission rather than on the Node.
func ParsePingParams(raw []byte) (PingParams, error) {
	p := PingParams{Count: defaultPingCount, TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	if p.Count < 1 || p.Count > maxPingCount {
		return p, fmt.Errorf("count must be between 1 and %d", maxPingCount)
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// ParseTCPParams decodes and defaults tcp parameters.
func ParseTCPParams(raw []byte) (TCPParams, error) {
	p := TCPParams{TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, fmt.Errorf("port must be between 1 and 65535")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// ParseHTTPParams decodes and defaults http parameters.
func ParseHTTPParams(raw []byte) (HTTPParams, error) {
	p := HTTPParams{Method: "GET", TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	p.Method = strings.ToUpper(p.Method)
	switch p.Method {
	case "GET", "HEAD":
	default:
		return p, fmt.Errorf("method must be GET or HEAD")
	}
	if p.ExpectedStatus != 0 && (p.ExpectedStatus < 100 || p.ExpectedStatus > 599) {
		return p, fmt.Errorf("expected_status must be a valid HTTP status code")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// ParseDNSParams decodes and defaults dns parameters.
func ParseDNSParams(raw []byte) (DNSParams, error) {
	p := DNSParams{RecordType: "A", TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	p.RecordType = strings.ToUpper(p.RecordType)
	switch p.RecordType {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS":
	default:
		return p, fmt.Errorf("record_type must be one of A, AAAA, CNAME, MX, TXT, NS")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// ParseTLSParams decodes and defaults tls parameters.
func ParseTLSParams(raw []byte) (TLSParams, error) {
	p := TLSParams{Port: 443, TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, fmt.Errorf("port must be between 1 and 65535")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// ParseSMTPParams decodes and defaults smtp parameters.
func ParseSMTPParams(raw []byte) (SMTPParams, error) {
	p := SMTPParams{Port: 25, TimeoutSeconds: defaultTimeoutSecs}
	if err := decodeParams(raw, &p); err != nil {
		return p, err
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, fmt.Errorf("port must be between 1 and 65535")
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > maxTimeoutSecs {
		return p, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSecs)
	}
	return p, nil
}

// Validate parses the parameters for a check type and reports whether they are
// acceptable. It is the platform-side validation hook (lifecycle Stage 2).
func Validate(checkType string, params []byte) error {
	var err error
	switch checkType {
	case TypePing:
		_, err = ParsePingParams(params)
	case TypeTCP:
		_, err = ParseTCPParams(params)
	case TypeHTTP:
		_, err = ParseHTTPParams(params)
	case TypeDNS:
		_, err = ParseDNSParams(params)
	case TypeTLS:
		_, err = ParseTLSParams(params)
	case TypeSMTP:
		_, err = ParseSMTPParams(params)
	default:
		err = fmt.Errorf("unsupported check type %q", checkType)
	}
	return err
}

// decodeParams unmarshals JSON params onto dst. An empty body is allowed —
// the caller's defaults stand.
func decodeParams(raw []byte, dst any) error {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("malformed parameters: %w", err)
	}
	return nil
}

// MustJSON marshals v to JSON, panicking on failure. It is used only for
// values that are statically known to be encodable (the measurement structs
// above), so a failure is a programming error.
func MustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("checkspec: unencodable value: " + err.Error())
	}
	return b
}
