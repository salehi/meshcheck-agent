// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
	"github.com/salehi/meshcheck-agent/pkg/checkspec"
)

// Outcome shorthands for the verbose generated enum constants.
const (
	outcomePass         = agentpb.ResultOutcome_RESULT_OUTCOME_PASS
	outcomeFail         = agentpb.ResultOutcome_RESULT_OUTCOME_FAIL
	outcomeInconclusive = agentpb.ResultOutcome_RESULT_OUTCOME_INCONCLUSIVE
	outcomeTimeout      = agentpb.ResultOutcome_RESULT_OUTCOME_TIMEOUT
)

// runCheck executes a Check of the given type against target and returns the
// outcome together with the JSON-encoded, type-specific measurements. It
// assumes check_type and params have already been validated.
func runCheck(ctx context.Context, checkType, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	switch checkType {
	case checkspec.TypePing:
		return runPing(ctx, target, params)
	case checkspec.TypeTCP:
		return runTCP(ctx, target, params)
	case checkspec.TypeHTTP:
		return runHTTP(ctx, target, params)
	case checkspec.TypeDNS:
		return runDNS(ctx, target, params)
	case checkspec.TypeTLS:
		return runTLS(ctx, target, params)
	case checkspec.TypeSMTP:
		return runSMTP(ctx, target, params)
	default:
		return outcomeInconclusive, checkspec.MustJSON(map[string]string{
			"error": "unsupported check type",
		})
	}
}

// icmpAvailable reports whether this agent can open an ICMP socket. It is
// probed once at startup to decide whether to advertise the "ping" capability.
func icmpAvailable() bool {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Traceroute tuning. The ping Check is a traceroute: it probes each TTL with a
// few ICMP echoes and records who answered. traceProbes per hop balances RTT
// signal against packet volume; traceMaxTTL bounds an unreachable route; the
// per-hop wait bounds how long we sit on a silent hop before moving on.
const (
	traceProbes     = 3
	traceMaxTTL     = 30
	tracePerHopWait = time.Second
	// sizeofSockExtendedErr is the size of struct sock_extended_err, after
	// which the IP_RECVERR control message carries the offender's sockaddr.
	sizeofSockExtendedErr = 16
)

// runPing traceroutes the target with TTL-limited ICMP echoes, recording the
// route hop by hop and deriving the final-hop loss / round-trip statistics. It
// uses an unprivileged datagram ICMP socket (no raw socket / CAP_NET_RAW),
// which requires net.ipv4.ping_group_range to include the agent's GID, plus the
// IP_RECVERR error queue to observe the ICMP Time Exceeded replies from routers
// along the path.
func runPing(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParsePingParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	addr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return outcomeFail, errMeasurements(err)
	}

	deadline := time.Now().Add(time.Duration(p.TimeoutSeconds) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	tr, err := traceroute(ctx, addr.IP, deadline)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}

	m := checkspec.PingMeasurements{
		PacketsSent: tr.finalSent,
		PacketsRecv: len(tr.finalRTTs),
		Hops:        tr.hops,
	}
	if addr.IP != nil {
		m.ResolvedIPs = []string{addr.IP.String()}
	}
	if m.PacketsSent > 0 {
		m.PacketLossPct = float64(m.PacketsSent-m.PacketsRecv) / float64(m.PacketsSent) * 100
	}
	if len(tr.finalRTTs) > 0 {
		m.RTTMinMs, m.RTTAvgMs, m.RTTMaxMs, m.RTTStdDevMs = rttStats(tr.finalRTTs)
	}

	outcome := outcomeFail
	switch {
	case tr.reached && len(tr.finalRTTs) > 0:
		outcome = outcomePass
	case !tr.reached && (ctx.Err() != nil || !time.Now().Before(deadline)):
		outcome = outcomeTimeout
	}
	return outcome, checkspec.MustJSON(m)
}

// traceResult is the outcome of a traceroute: the ordered route, and the
// final-hop probe statistics that stand in for the classic ping measurement.
type traceResult struct {
	hops      []checkspec.Hop
	finalSent int             // probes sent at the hop that reached the target
	finalRTTs []time.Duration // round-trip times of those that came back
	reached   bool            // the target itself answered
}

// traceroute walks the path to dst, sending traceProbes echoes at each TTL and
// recording who replied, until the target answers or the route is exhausted.
func traceroute(ctx context.Context, dst net.IP, deadline time.Time) (traceResult, error) {
	var res traceResult
	dst4 := dst.To4()
	if dst4 == nil {
		return res, fmt.Errorf("ping: target %q is not an IPv4 address", dst)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return res, fmt.Errorf("open icmp socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return res, fmt.Errorf("enable ip_recverr: %w", err)
	}
	_ = unix.SetNonblock(fd, true)

	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst4)

	seq := 0
	sentAt := make(map[int]time.Time)

	for ttl := 1; ttl <= traceMaxTTL; ttl++ {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return res, fmt.Errorf("set ttl: %w", err)
		}

		hop := checkspec.Hop{TTL: ttl}
		pending := map[int]bool{}
		for i := 0; i < traceProbes; i++ {
			seq++
			wire, err := (&icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{ID: 0, Seq: seq, Data: []byte("meshcheck")},
			}).Marshal(nil)
			if err != nil {
				continue
			}
			if err := unix.Sendto(fd, wire, 0, &sa); err != nil {
				continue
			}
			sentAt[seq] = time.Now()
			pending[seq] = true
		}
		probesSent := len(pending)
		if probesSent == 0 {
			continue
		}

		hopDeadline := time.Now().Add(tracePerHopWait)
		if hopDeadline.After(deadline) {
			hopDeadline = deadline
		}
		reachedHere := collectHop(fd, &hop, pending, sentAt, &res, hopDeadline)

		res.hops = append(res.hops, hop)
		if reachedHere {
			res.hops[len(res.hops)-1].Target = true
			res.reached = true
			res.finalSent = probesSent
			break
		}
	}
	return res, nil
}

// collectHop reads replies for one TTL until every probe is accounted for or the
// hop deadline passes, filling hop.IP / hop.RTTMs and, when the target itself
// answers, the final-hop RTTs on res. It reports whether the target was reached.
func collectHop(fd int, hop *checkspec.Hop, pending map[int]bool, sentAt map[int]time.Time, res *traceResult, hopDeadline time.Time) bool {
	reached := false
	for len(pending) > 0 {
		waitMs := int(time.Until(hopDeadline) / time.Millisecond)
		if waitMs <= 0 {
			break
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(pfd, waitMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			break
		}
		if n == 0 {
			break // hop went silent
		}
		// ICMP Time Exceeded from routers arrives on the error queue.
		if pfd[0].Revents&unix.POLLERR != 0 {
			for {
				ip, s, ok := readErrQueue(fd)
				if !ok {
					break
				}
				if !pending[s] { // not a probe outstanding for this hop
					continue
				}
				if hop.IP == "" {
					hop.IP = ip
				}
				hop.RTTMs = append(hop.RTTMs, msOf(time.Since(sentAt[s])))
				delete(pending, s)
			}
		}
		// An Echo Reply means the probe reached the target itself.
		if pfd[0].Revents&unix.POLLIN != 0 {
			for {
				ip, s, isReply, ok := readEchoReply(fd)
				if !ok {
					break
				}
				if !isReply || !pending[s] {
					continue
				}
				if hop.IP == "" {
					hop.IP = ip
				}
				rtt := time.Since(sentAt[s])
				hop.RTTMs = append(hop.RTTMs, msOf(rtt))
				res.finalRTTs = append(res.finalRTTs, rtt)
				reached = true
				delete(pending, s)
			}
		}
	}
	return reached
}

// readErrQueue reads one queued ICMP error and returns the offending router's
// IP and the sequence number of the echo that provoked it. ok is false once the
// error queue is drained (EAGAIN).
func readErrQueue(fd int) (ip string, seq int, ok bool) {
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		return "", 0, false
	}
	return offenderIP(oob[:oobn]), echoSeq(buf[:n]), true
}

// readEchoReply reads one normally-delivered ICMP datagram, returning the
// source IP, the echo sequence, and whether it was an Echo Reply. ok is false
// once nothing more is queued (EAGAIN).
func readEchoReply(fd int) (ip string, seq int, isReply, ok bool) {
	buf := make([]byte, 1500)
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return "", 0, false, false
	}
	if from4, isV4 := from.(*unix.SockaddrInet4); isV4 {
		ip = net.IP(from4.Addr[:]).String()
	}
	msg, err := icmp.ParseMessage(1 /* IPv4 ICMP */, buf[:n])
	if err != nil {
		return ip, 0, false, true
	}
	if echo, isEcho := msg.Body.(*icmp.Echo); isEcho && msg.Type == ipv4.ICMPTypeEchoReply {
		return ip, echo.Seq, true, true
	}
	return ip, 0, false, true
}

// offenderIP extracts the router address from an IP_RECVERR control message:
// the offender's sockaddr_in follows the struct sock_extended_err. It returns
// "" when no usable address is present.
func offenderIP(oob []byte) string {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return ""
	}
	for _, c := range cmsgs {
		if c.Header.Level != unix.IPPROTO_IP || c.Header.Type != unix.IP_RECVERR {
			continue
		}
		// sockaddr_in: family(2) port(2) addr(4); addr is at offset +4.
		off := sizeofSockExtendedErr + 4
		if len(c.Data) < off+4 {
			continue
		}
		ip := net.IPv4(c.Data[off], c.Data[off+1], c.Data[off+2], c.Data[off+3])
		if ip.Equal(net.IPv4zero) {
			continue
		}
		return ip.String()
	}
	return ""
}

// echoSeq pulls the sequence number out of an ICMP echo, whether the bytes
// begin at the ICMP header or behind a 20-byte IPv4 header (as the error queue
// sometimes returns the original packet). It returns -1 when none is found.
func echoSeq(b []byte) int {
	for _, off := range []int{0, 20} {
		if len(b) <= off {
			continue
		}
		if msg, err := icmp.ParseMessage(1 /* IPv4 ICMP */, b[off:]); err == nil {
			if echo, ok := msg.Body.(*icmp.Echo); ok {
				return echo.Seq
			}
		}
	}
	return -1
}

// runTCP opens a TCP connection to target:port and reports whether it
// succeeded and how long it took.
func runTCP(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParseTCPParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()

	addr := net.JoinHostPort(target, strconv.Itoa(p.Port))
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	latency := time.Since(start)
	if err != nil {
		m := checkspec.TCPMeasurements{Connected: false, LatencyMs: msOf(latency)}
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}
	_ = conn.Close()
	return outcomePass, checkspec.MustJSON(checkspec.TCPMeasurements{
		Connected: true,
		LatencyMs: msOf(latency),
	})
}

// runHTTP performs an HTTP request and reports the status code, total latency,
// and time to first byte.
func runHTTP(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParseHTTPParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()

	var start time.Time
	var ttfb time.Duration
	var resolvedIPs []string
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb = time.Since(start) },
		DNSDone: func(di httptrace.DNSDoneInfo) {
			for _, a := range di.Addrs {
				resolvedIPs = append(resolvedIPs, a.IP.String())
			}
		},
	}
	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(reqCtx, trace), p.Method, target, nil)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}

	start = time.Now()
	resp, err := http.DefaultClient.Do(req)
	latency := time.Since(start)
	if err != nil {
		m := checkspec.HTTPMeasurements{LatencyMs: msOf(latency), ResolvedIPs: resolvedIPs}
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	m := checkspec.HTTPMeasurements{
		StatusCode:  resp.StatusCode,
		LatencyMs:   msOf(latency),
		TTFBMs:      msOf(ttfb),
		ResolvedIPs: resolvedIPs,
	}
	outcome := outcomeFail
	if statusMatches(resp.StatusCode, p.ExpectedStatus) {
		outcome = outcomePass
	}
	return outcome, checkspec.MustJSON(m)
}

// runDNS resolves target for the requested record type and reports the
// records found and how long resolution took.
func runDNS(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParseDNSParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()

	start := time.Now()
	var nameserver string
	records, err := resolveDNS(lookupCtx, p.RecordType, target, &nameserver)
	latency := time.Since(start)

	m := checkspec.DNSMeasurements{RecordType: p.RecordType, LatencyMs: msOf(latency), Nameserver: nameserver}
	if err != nil {
		// A timeout is distinct from an outright resolution failure
		// (NXDOMAIN, an empty record set) so the Verdict can tell them apart.
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}
	m.Resolved = true
	m.Records = records
	m.RecordCount = len(records)
	return outcomePass, checkspec.MustJSON(m)
}

// resolveDNS performs the lookup for one record type and renders the records
// as strings. An empty record set is reported as an error so it fails rather
// than passing with nothing found. It records the resolver endpoint it actually
// dialed into *nameserver (e.g. "127.0.0.11:53").
//
// PreferGo forces Go's pure-Go resolver so the Dial hook fires reliably — with
// the cgo resolver the hook is bypassed and the nameserver would go uncaptured.
func resolveDNS(ctx context.Context, recordType, host string, nameserver *string) ([]string, error) {
	dialer := &net.Dialer{}
	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err == nil && nameserver != nil {
				*nameserver = address
			}
			return conn, err
		},
	}
	switch recordType {
	case "A", "AAAA":
		network := "ip4"
		if recordType == "AAAA" {
			network = "ip6"
		}
		ips, err := r.LookupIP(ctx, network, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, len(ips))
		for i, ip := range ips {
			out[i] = ip.String()
		}
		return nonEmpty(out)
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, host)
		if err != nil {
			return nil, err
		}
		return nonEmpty([]string{cname})
	case "MX":
		mxs, err := r.LookupMX(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, len(mxs))
		for i, mx := range mxs {
			out[i] = fmt.Sprintf("%d %s", mx.Pref, mx.Host)
		}
		return nonEmpty(out)
	case "TXT":
		txts, err := r.LookupTXT(ctx, host)
		if err != nil {
			return nil, err
		}
		return nonEmpty(txts)
	case "NS":
		nss, err := r.LookupNS(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, len(nss))
		for i, ns := range nss {
			out[i] = ns.Host
		}
		return nonEmpty(out)
	default:
		return nil, fmt.Errorf("unsupported record type %q", recordType)
	}
}

// nonEmpty turns an empty record set into an explicit error.
func nonEmpty(records []string) ([]string, error) {
	if len(records) == 0 {
		return nil, errors.New("no records found")
	}
	return records, nil
}

// runTLS performs a TLS handshake with target and reports the negotiated
// parameters and the leaf certificate's validity and expiry. The handshake is
// done without verification so the certificate details are captured even when
// the certificate is invalid or expired; validity is then checked explicitly.
func runTLS(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParseTLSParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()

	addr := net.JoinHostPort(target, strconv.Itoa(p.Port))
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: target, InsecureSkipVerify: true}}
	start := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	latency := time.Since(start)

	m := checkspec.TLSMeasurements{LatencyMs: msOf(latency)}
	if err != nil {
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	m.HandshakeOK = true
	m.TLSVersion = tlsVersionName(state.Version)
	m.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) == 0 {
		return outcomeFail, checkspec.MustJSON(m)
	}

	leaf := state.PeerCertificates[0]
	m.CertSubject = leaf.Subject.CommonName
	m.CertIssuer = leaf.Issuer.CommonName
	m.CertExpiresAt = leaf.NotAfter.UTC().Format(time.RFC3339)
	m.CertDaysRemaining = int(time.Until(leaf.NotAfter).Hours() / 24)
	m.CertValid = verifyCertChain(state, target)

	if m.CertValid {
		return outcomePass, checkspec.MustJSON(m)
	}
	return outcomeFail, checkspec.MustJSON(m)
}

// verifyCertChain reports whether the presented certificate chain is trusted
// for host: it builds to a system root, the hostname matches, and nothing in
// the chain has expired.
func verifyCertChain(state tls.ConnectionState, host string) bool {
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	})
	return err == nil
}

// tlsVersionName renders a TLS version constant as its dotted version number.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return "unknown"
	}
}

// runSMTP connects to an SMTP service, reads its greeting, and issues EHLO.
// The Check passes when the server greets with a 220 and accepts EHLO; the
// measurements also record whether STARTTLS is advertised.
func runSMTP(ctx context.Context, target string, params []byte) (agentpb.ResultOutcome, []byte) {
	p, err := checkspec.ParseSMTPParams(params)
	if err != nil {
		return outcomeInconclusive, errMeasurements(err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()

	addr := net.JoinHostPort(target, strconv.Itoa(p.Port))
	var dialer net.Dialer
	start := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	latency := time.Since(start)

	m := checkspec.SMTPMeasurements{LatencyMs: msOf(latency)}
	if err != nil {
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}
	defer conn.Close()
	m.Connected = true

	// Bound the whole SMTP conversation by the remaining check budget.
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	text := textproto.NewConn(conn)
	defer text.Close()

	// The greeting — a healthy server answers 220.
	code, banner, err := text.ReadResponse(220)
	m.BannerCode = code
	m.Banner = firstLine(banner)
	if err != nil {
		if isTimeout(err) {
			return outcomeTimeout, checkspec.MustJSON(m)
		}
		return outcomeFail, checkspec.MustJSON(m)
	}

	// EHLO — and note whether STARTTLS is among the advertised extensions.
	if err := text.PrintfLine("EHLO meshcheck"); err == nil {
		if _, ehlo, err := text.ReadResponse(250); err == nil {
			m.EHLOOK = true
			m.STARTTLSAdvertised = strings.Contains(strings.ToUpper(ehlo), "STARTTLS")
		}
	}
	_ = text.PrintfLine("QUIT")

	if m.EHLOOK {
		return outcomePass, checkspec.MustJSON(m)
	}
	return outcomeFail, checkspec.MustJSON(m)
}

// firstLine returns the first line of s.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// statusMatches reports whether an HTTP status is acceptable: equal to the
// expected code, or — when no specific code was requested — any 2xx.
func statusMatches(got, expected int) bool {
	if expected != 0 {
		return got == expected
	}
	return got/100 == 2
}

// rttStats returns the min, average, max, and population standard deviation of
// a set of round-trip times, in milliseconds.
func rttStats(rtts []time.Duration) (min, avg, max, stddev float64) {
	min = msOf(rtts[0])
	max = msOf(rtts[0])
	var sum float64
	for _, d := range rtts {
		ms := msOf(d)
		sum += ms
		if ms < min {
			min = ms
		}
		if ms > max {
			max = ms
		}
	}
	avg = sum / float64(len(rtts))
	var sumSq float64
	for _, d := range rtts {
		diff := msOf(d) - avg
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / float64(len(rtts)))
	return min, avg, max, stddev
}

// msOf converts a duration to fractional milliseconds.
func msOf(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// isTimeout reports whether an error is a deadline/timeout rather than an
// outright failure such as connection refused.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// errMeasurements packages an executor-side error into a measurements blob so
// the failure is still visible in the stored Result.
func errMeasurements(err error) []byte {
	return checkspec.MustJSON(map[string]string{"error": err.Error()})
}
