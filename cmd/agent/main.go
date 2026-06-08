// SPDX-License-Identifier: AGPL-3.0-only

// Command agent is the MeshCheck Node agent.
//
// It connects to the platform's agent gateway over a Protobuf-over-WebSocket
// stream, advertises its capabilities, and executes the Checks the platform
// dispatches (ping, TCP connect, HTTP). Every Result is signed with the
// Node's Ed25519 key.
//
// Usage:
//
//	agent           run the agent (default)
//	agent init      write a starter config file (0600) and exit
//	agent --version print the build version and exit
//
// Configuration is resolved from a JSON config file and then the environment,
// with the environment taking precedence. The config file is found at
// MESHCHECK_AGENT_CONFIG, or /etc/meshcheck/agent.json when that is unset.
// Recognised settings (config-file key / environment variable):
//
//	api_key              / MESHCHECK_AGENT_API_KEY            (required)
//	gateway_url          / MESHCHECK_AGENT_GATEWAY_URL        (required)
//	key_file             / MESHCHECK_AGENT_KEY_FILE           signing-key path
//	city                 / MESHCHECK_AGENT_CITY               self-declared city
//	country              / MESHCHECK_AGENT_COUNTRY            self-declared ISO 3166-1 alpha-2
//	connection_class     / MESHCHECK_AGENT_CONNECTION_CLASS   vps | residential_wired | ...
//	log_level            / MESHCHECK_AGENT_LOG_LEVEL          debug | info | warn | error
//	max_concurrent_tasks / MESHCHECK_AGENT_MAX_CONCURRENT_TASKS  agent-side Task ceiling
//	auto_update          / MESHCHECK_AGENT_AUTO_UPDATE        replace own binary on a signed release (default off)
//
// The config file holds the API key and must not be group- or world-readable.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/salehi/meshcheck-agent/internal/obslog"
)

const defaultKeyFile = "/var/lib/meshcheck/agent.key"

// reconnect backoff bounds.
const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

func main() {
	// `agent --version` prints the build-time version and exits. The
	// self-updater execs a freshly downloaded binary this way to confirm it
	// runs and reports the version it claims to be before swapping it in.
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(agentVersion)
		return
	}

	// `agent init` writes a starter config file and exits — it loads no
	// configuration and opens no connection.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		path := defaultConfigPath
		if p := os.Getenv("MESHCHECK_AGENT_CONFIG"); p != "" {
			path = p
		}
		if err := writeTemplateConfig(path); err != nil {
			fmt.Fprintln(os.Stderr, "fatal:", err)
			os.Exit(1)
		}
		fmt.Printf("wrote starter config to %s — set api_key and gateway_url, then run `agent`\n", path)
		return
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log := obslog.NewLogger(cfg.LogLevel)

	priv, err := loadOrCreateKey(cfg.KeyFile)
	if err != nil {
		return err
	}

	client := newClient(cfg, priv, log)
	log.Info("meshcheck agent starting",
		"gateway", cfg.GatewayURL, "capabilities", client.checkTypes,
		"max_concurrent_tasks", cfg.MaxConcurrentTasks)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Reconnect loop: a clean disconnect retries with exponential backoff; a
	// successful session resets the backoff so a long-lived connection that
	// later drops reconnects promptly.
	backoff := minBackoff
	for ctx.Err() == nil {
		connected, cooldown := client.Run(ctx)
		if connected {
			backoff = minBackoff
		}
		if cooldown == 0 {
			cooldown = backoff
			backoff = min(backoff*2, maxBackoff)
		}
		select {
		case <-ctx.Done():
		case <-time.After(cooldown):
		}
	}
	log.Info("meshcheck agent stopped")
	return nil
}
