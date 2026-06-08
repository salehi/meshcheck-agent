// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
	"github.com/salehi/meshcheck-agent/pkg/release"
	"github.com/salehi/meshcheck-agent/pkg/version"
)

const (
	// updateHTTPTimeout bounds each manifest/binary download.
	updateHTTPTimeout = 2 * time.Minute
	// updateDrainTimeout bounds how long a non-mandatory update waits for
	// in-flight tasks to finish before restarting.
	updateDrainTimeout = 60 * time.Second
	// updateRetryCooldown is how long a failed attempt at a given target version
	// is remembered (persisted next to the key file) so a process that keeps
	// restarting does not re-download the same release in a tight loop. After it
	// elapses the agent will try that target again; a transient failure is not a
	// permanent block.
	updateRetryCooldown = 6 * time.Hour
	// maxBinarySize caps a downloaded artifact, a guard against a runaway body.
	maxBinarySize = 256 << 20 // 256 MiB
)

// handleUpdate processes an UpdateAvailable offer: it verifies and applies a
// signed release, then restarts so the new binary takes over. Every failure is
// non-fatal — the agent keeps running the current version and is offered the
// update again on its next reconnect.
func (c *Client) handleUpdate(ctx context.Context, msg *agentpb.UpdateAvailable) {
	target := msg.GetTargetVersion()

	// Act on a given target at most once per process; ignore repeat offers
	// (the platform re-offers on every connection).
	c.updateMu.Lock()
	if c.updateActive || c.attemptedVersion == target {
		c.updateMu.Unlock()
		return
	}
	c.updateActive = true
	c.attemptedVersion = target
	c.updateMu.Unlock()
	defer func() {
		c.updateMu.Lock()
		c.updateActive = false
		c.updateMu.Unlock()
	}()

	if err := c.applyUpdate(ctx, msg); err != nil {
		c.log.Warn("self-update skipped", "target", target, "error", err)
	}
}

// applyUpdate runs the gate checks, downloads and verifies the release, swaps
// the binary, and restarts. It returns an error describing why an update did
// not happen; a nil return means the process is on its way down for a restart.
func (c *Client) applyUpdate(ctx context.Context, msg *agentpb.UpdateAvailable) error {
	target := msg.GetTargetVersion()

	// --- Gate checks ---
	if !c.cfg.AutoUpdate {
		return errors.New("auto-update disabled in config")
	}
	if releasePubB64 == "" {
		return errors.New("this build has no embedded release key (dev build)")
	}
	if !version.Less(agentVersion, target) {
		return fmt.Errorf("offered %s is not newer than %s", target, agentVersion)
	}
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}
	binDir := filepath.Dir(binPath)
	if !writable(binDir) {
		return fmt.Errorf("binary directory %q is not writable", binDir)
	}
	if c.recentlyFailed(target) {
		return fmt.Errorf("target %s failed recently; waiting out the cooldown", target)
	}
	c.recordAttempt(target)

	c.log.Info("self-update starting", "from", agentVersion, "to", target, "manifest", msg.GetManifestUrl())

	// --- Fetch and verify the manifest ---
	manifest, err := c.fetchManifest(ctx, msg.GetManifestUrl(), target)
	if err != nil {
		return err
	}
	plat := runtime.GOOS + "/" + runtime.GOARCH
	artifact, ok := manifest.Artifacts[plat]
	if !ok {
		return fmt.Errorf("manifest has no artifact for %s", plat)
	}

	// --- Fetch and verify the binary, staged next to the current one ---
	artifactURL, err := resolveRef(msg.GetManifestUrl(), artifact.Filename)
	if err != nil {
		return err
	}
	newPath := filepath.Join(binDir, ".meshcheck-agent.new")
	if err := c.downloadBinary(ctx, artifactURL, artifact.SHA256, newPath); err != nil {
		os.Remove(newPath)
		return err
	}
	defer os.Remove(newPath) // no-op once the rename below succeeds

	// --- Prove the new binary runs and is the version it claims ---
	if err := verifyBinaryVersion(newPath, target); err != nil {
		return err
	}

	// --- Atomic swap (replacing a running executable is fine on Linux) ---
	if err := os.Rename(newPath, binPath); err != nil {
		return fmt.Errorf("swap binary: %w", err)
	}
	c.log.Info("self-update applied; restarting", "version", target, "path", binPath)

	// --- Restart so the new binary takes over ---
	c.restart(msg.GetMandatory())
	return nil
}

// fetchManifest downloads the manifest and its detached signature, verifies the
// signature against the embedded release key, and confirms it names the target.
func (c *Client) fetchManifest(ctx context.Context, manifestURL, target string) (release.Manifest, error) {
	manifestBytes, err := httpGet(ctx, manifestURL, 1<<20)
	if err != nil {
		return release.Manifest{}, fmt.Errorf("download manifest: %w", err)
	}
	sigURL, err := resolveRef(manifestURL, baseName(manifestURL)+".sig")
	if err != nil {
		return release.Manifest{}, err
	}
	sigBytes, err := httpGet(ctx, sigURL, 1<<16)
	if err != nil {
		return release.Manifest{}, fmt.Errorf("download signature: %w", err)
	}
	if err := release.Verify(releasePubB64, manifestBytes, strings.TrimSpace(string(sigBytes))); err != nil {
		return release.Manifest{}, err
	}
	m, err := release.Parse(manifestBytes)
	if err != nil {
		return release.Manifest{}, err
	}
	if m.Version != target {
		return release.Manifest{}, fmt.Errorf("manifest version %q does not match offered target %q", m.Version, target)
	}
	return m, nil
}

// downloadBinary streams the artifact tarball, verifies its SHA-256, extracts
// the meshcheck-agent binary, and writes it to dst with 0755 permissions.
func (c *Client) downloadBinary(ctx context.Context, artifactURL, wantSHA, dst string) error {
	reqCtx, cancel := context.WithTimeout(ctx, updateHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download artifact: HTTP %d", resp.StatusCode)
	}

	// Hash the exact bytes we received, then extract from those same bytes.
	hasher := sha256.New()
	tarball, err := io.ReadAll(io.LimitReader(io.TeeReader(resp.Body, hasher), maxBinarySize))
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); !strings.EqualFold(got, wantSHA) {
		return fmt.Errorf("artifact sha256 mismatch: got %s, want %s", got, wantSHA)
	}
	return extractAgentBinary(tarball, dst)
}

// extractAgentBinary pulls the meshcheck-agent file out of a gzipped tar and
// writes it to dst (0755).
func extractAgentBinary(tarball []byte, dst string) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("artifact does not contain meshcheck-agent")
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "meshcheck-agent" {
			continue
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create staged binary: %w", err)
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxBinarySize)); err != nil {
			out.Close()
			return fmt.Errorf("write staged binary: %w", err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("close staged binary: %w", err)
		}
		return os.Chmod(dst, 0o755)
	}
}

// verifyBinaryVersion runs `<path> --version` and confirms the output matches
// want — a cheap proof the staged binary executes on this host and is the
// version the manifest claims, before it replaces the running one.
func verifyBinaryVersion(path, want string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return fmt.Errorf("staged binary self-test failed: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		return fmt.Errorf("staged binary reports version %q, want %q", got, want)
	}
	return nil
}

// restart hands control to the freshly swapped binary. The agent runs under a
// service manager with a restart policy (systemd Restart=always), so a clean
// exit relaunches it from the new binary. A clean exit — rather than
// syscall.Exec — is deliberate: systemd re-applies the unit's
// AmbientCapabilities (CAP_NET_RAW) on each start, which a re-exec under
// NoNewPrivileges could otherwise drop. A mandatory update exits at once;
// otherwise it lets in-flight tasks drain first.
func (c *Client) restart(mandatory bool) {
	if !mandatory {
		deadline := time.Now().Add(updateDrainTimeout)
		for len(c.sem) > 0 && time.Now().Before(deadline) {
			time.Sleep(time.Second)
		}
	}
	c.log.Info("exiting for restart on the updated binary", "version", agentVersion)
	os.Exit(0)
}

// --- attempt marker (crash-loop guard) ---

// attemptMarkerPath returns the path of the per-version attempt marker, kept
// next to the signing key (a directory the agent already owns and persists).
func (c *Client) attemptMarkerPath() string {
	return filepath.Join(filepath.Dir(c.cfg.KeyFile), ".update-attempt")
}

// recentlyFailed reports whether target was attempted within updateRetryCooldown.
func (c *Client) recentlyFailed(target string) bool {
	data, err := os.ReadFile(c.attemptMarkerPath())
	if err != nil {
		return false
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), " ", 2)
	if len(parts) != 2 || parts[0] != target {
		return false
	}
	ms, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.UnixMilli(ms)) < updateRetryCooldown
}

// recordAttempt persists that target was attempted now. Best-effort: a write
// failure only weakens the crash-loop guard, it does not block the update.
func (c *Client) recordAttempt(target string) {
	line := fmt.Sprintf("%s %d", target, time.Now().UnixMilli())
	if err := os.WriteFile(c.attemptMarkerPath(), []byte(line), 0o600); err != nil {
		c.log.Warn("could not record update attempt", "error", err)
	}
}

// --- small helpers ---

// httpGet fetches a URL and returns the body, capped at limit bytes.
func httpGet(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, updateHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// resolveRef resolves a possibly-relative reference against a base URL.
func resolveRef(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base URL %q: %w", base, err)
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("parse reference %q: %w", ref, err)
	}
	return b.ResolveReference(r).String(), nil
}

// baseName returns the last path element of a URL (its filename).
func baseName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return filepath.Base(u.Path)
	}
	return filepath.Base(rawURL)
}

// writable reports whether dir can be written to, by creating and removing a
// probe file.
func writable(dir string) bool {
	probe := filepath.Join(dir, ".meshcheck-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}
