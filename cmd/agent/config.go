// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// defaultConfigPath is where the agent looks for its config file when
// MESHCHECK_AGENT_CONFIG is unset. Contributors on macOS or Windows, where
// this path is unusual, set MESHCHECK_AGENT_CONFIG explicitly.
const defaultConfigPath = "/etc/meshcheck/agent.json"

// defaultMaxConcurrentTasks is the agent's own ceiling on Tasks run at once.
// The effective ceiling is the smaller of this and the platform's advertised
// limit, so a modest home machine never overcommits.
const defaultMaxConcurrentTasks = 3

// Config is the agent's runtime configuration.
type Config struct {
	APIKey             string
	GatewayURL         string
	KeyFile            string
	Name               string
	City               string
	Country            string
	ConnectionClass    string
	LogLevel           string
	MaxConcurrentTasks int
	// AutoUpdate lets the agent replace its own binary when the platform offers
	// a newer signed release. Off by default so a build can never be talked
	// into updating itself unless the install opted in; the systemd installer
	// sets it true, while the container fleet (env-only) leaves it off.
	AutoUpdate bool
}

// fileConfig mirrors the JSON config file. Fields are pointers so an absent
// key is distinguishable from one deliberately set to a zero value.
type fileConfig struct {
	APIKey             *string `json:"api_key"`
	GatewayURL         *string `json:"gateway_url"`
	KeyFile            *string `json:"key_file"`
	Name               *string `json:"name"`
	City               *string `json:"city"`
	Country            *string `json:"country"`
	ConnectionClass    *string `json:"connection_class"`
	LogLevel           *string `json:"log_level"`
	MaxConcurrentTasks *int    `json:"max_concurrent_tasks"`
	AutoUpdate         *bool   `json:"auto_update"`
}

// loadConfig resolves the agent configuration: defaults first, then the config
// file if one is present, then environment variables — so an operator can
// override any file value without editing the file (the simulated VPS fleet
// relies on this, configuring agents purely through the environment).
func loadConfig() (Config, error) {
	cfg := Config{
		KeyFile:            defaultKeyFile,
		ConnectionClass:    "vps",
		LogLevel:           "info",
		MaxConcurrentTasks: defaultMaxConcurrentTasks,
	}

	if path := configPath(); path != "" {
		if err := applyConfigFile(&cfg, path); err != nil {
			return Config{}, err
		}
	}
	applyEnv(&cfg)

	var missing []string
	if cfg.APIKey == "" {
		missing = append(missing, "api_key (or MESHCHECK_AGENT_API_KEY)")
	}
	if cfg.GatewayURL == "" {
		missing = append(missing, "gateway_url (or MESHCHECK_AGENT_GATEWAY_URL)")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required configuration: %v", missing)
	}
	if cfg.MaxConcurrentTasks < 1 {
		return Config{}, fmt.Errorf("max_concurrent_tasks must be at least 1")
	}
	return cfg, nil
}

// configPath returns the config-file path to load, or "" if there is none:
// MESHCHECK_AGENT_CONFIG when set, otherwise defaultConfigPath if it exists.
func configPath() string {
	if p := os.Getenv("MESHCHECK_AGENT_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath
	}
	return ""
}

// applyConfigFile overlays a JSON config file onto cfg. The file holds the
// Node's API key, so it must not be readable by group or other — the agent
// refuses to start from a world- or group-accessible config file.
func applyConfigFile(cfg *Config, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config file %q is group/world-accessible (%o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return fmt.Errorf("parse config file %q: %w", path, err)
	}

	setString(&cfg.APIKey, fc.APIKey)
	setString(&cfg.GatewayURL, fc.GatewayURL)
	setString(&cfg.KeyFile, fc.KeyFile)
	setString(&cfg.Name, fc.Name)
	setString(&cfg.City, fc.City)
	setString(&cfg.Country, fc.Country)
	setString(&cfg.ConnectionClass, fc.ConnectionClass)
	setString(&cfg.LogLevel, fc.LogLevel)
	if fc.MaxConcurrentTasks != nil {
		cfg.MaxConcurrentTasks = *fc.MaxConcurrentTasks
	}
	if fc.AutoUpdate != nil {
		cfg.AutoUpdate = *fc.AutoUpdate
	}
	return nil
}

// applyEnv overlays environment variables onto cfg; an unset variable leaves
// the existing value untouched.
func applyEnv(cfg *Config) {
	envString(&cfg.APIKey, "MESHCHECK_AGENT_API_KEY")
	envString(&cfg.GatewayURL, "MESHCHECK_AGENT_GATEWAY_URL")
	envString(&cfg.KeyFile, "MESHCHECK_AGENT_KEY_FILE")
	envString(&cfg.Name, "MESHCHECK_AGENT_NAME")
	envString(&cfg.City, "MESHCHECK_AGENT_CITY")
	envString(&cfg.Country, "MESHCHECK_AGENT_COUNTRY")
	envString(&cfg.ConnectionClass, "MESHCHECK_AGENT_CONNECTION_CLASS")
	envString(&cfg.LogLevel, "MESHCHECK_AGENT_LOG_LEVEL")
	if v := os.Getenv("MESHCHECK_AGENT_MAX_CONCURRENT_TASKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxConcurrentTasks = n
		}
	}
	if v := os.Getenv("MESHCHECK_AGENT_AUTO_UPDATE"); v != "" {
		cfg.AutoUpdate = v == "1" || strings.EqualFold(v, "true")
	}
}

func setString(dst *string, src *string) {
	if src != nil && *src != "" {
		*dst = *src
	}
}

func envString(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

// writeTemplateConfig writes a starter config file with 0600 permissions for
// the `agent init` onboarding command. It refuses to overwrite an existing
// file so a configured Node's credentials are never clobbered.
func writeTemplateConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check config path %q: %w", path, err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}
	const template = `{
  "api_key": "",
  "gateway_url": "ws://localhost:8080/agent",
  "key_file": "/var/lib/meshcheck/agent.key",
  "name": "",
  "city": "",
  "country": "",
  "connection_class": "residential_wired",
  "log_level": "info",
  "max_concurrent_tasks": 3,
  "auto_update": true
}
`
	if err := os.WriteFile(path, []byte(template), 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}
