// advanced_server is a comprehensive hook server with a web UI for configuring:
//   - Basic access/pre/post rules (blocking users, filtering data, content-based blocking)
//   - PII redaction (emails, IPs, SSNs, phone numbers, credit cards, dates of birth)
//   - A/B and canary testing (route tool calls to different versions/servers)
//
// Configuration is stored in a YAML file with hot-reload support.
// All features can be managed through the built-in web dashboard.
//
// Usage:
//
//	go run ./examples/advanced_server -port 8888 -config config.yaml
//	go run ./examples/advanced_server -port 8888 -token secret123
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// Request Logging
// =============================================================================

// RequestLog stores information about each incoming request.
type RequestLog struct {
	Timestamp time.Time   `json:"timestamp"`
	Endpoint  string      `json:"endpoint"`
	Body      interface{} `json:"body"`
	Response  interface{} `json:"response"`
	RuleMatch string      `json:"rule_match,omitempty"`
	PIIFound  bool        `json:"pii_found,omitempty"`
	ABVariant string      `json:"ab_variant,omitempty"`
}

// =============================================================================
// Server
// =============================================================================

// ServerConfig holds CLI configuration for the server.
type ServerConfig struct {
	Port       int
	Token      string
	Verbose    bool
	ConfigFile string

	// TLS/mTLS
	TLSEnabled bool
	CertFile   string
	KeyFile    string
	CAFile     string
}

// HookServer implements the webhook ServerInterface with rules, PII redaction, and A/B testing.
type HookServer struct {
	mu        sync.RWMutex
	logs      []RequestLog
	serverCfg *ServerConfig
	cfgMgr    *ConfigManager
	abMgr     *ABTestManager
}

// NewHookServer creates a new server instance.
func NewHookServer(serverCfg *ServerConfig, cfgMgr *ConfigManager) *HookServer {
	return &HookServer{
		logs:      make([]RequestLog, 0),
		serverCfg: serverCfg,
		cfgMgr:    cfgMgr,
		abMgr:     NewABTestManager(),
	}
}

func (s *HookServer) logRequest(endpoint string, body, response interface{}, ruleMatch string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := RequestLog{
		Timestamp: time.Now(),
		Endpoint:  endpoint,
		Body:      body,
		Response:  response,
		RuleMatch: ruleMatch,
	}
	s.logs = append(s.logs, entry)

	if s.serverCfg.Verbose {
		jsonBody, _ := json.MarshalIndent(body, "", "  ")
		jsonResp, _ := json.MarshalIndent(response, "", "  ")
		fmt.Printf("\n[%s] %s\n", time.Now().Format("15:04:05"), endpoint)
		if ruleMatch != "" {
			fmt.Printf("Rule matched: %s\n", ruleMatch)
		}
		fmt.Printf("Request:\n%s\n", string(jsonBody))
		fmt.Printf("Response:\n%s\n", string(jsonResp))
		fmt.Println(strings.Repeat("-", 60))
	}
}

func (s *HookServer) logRequestFull(endpoint string, body, response interface{}, ruleMatch string, piiFound bool, abVariant string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := RequestLog{
		Timestamp: time.Now(),
		Endpoint:  endpoint,
		Body:      body,
		Response:  response,
		RuleMatch: ruleMatch,
		PIIFound:  piiFound,
		ABVariant: abVariant,
	}
	s.logs = append(s.logs, entry)

	if s.serverCfg.Verbose {
		jsonBody, _ := json.MarshalIndent(body, "", "  ")
		jsonResp, _ := json.MarshalIndent(response, "", "  ")
		fmt.Printf("\n[%s] %s\n", time.Now().Format("15:04:05"), endpoint)
		if ruleMatch != "" {
			fmt.Printf("Rule matched: %s\n", ruleMatch)
		}
		if piiFound {
			fmt.Printf("PII detected and handled\n")
		}
		if abVariant != "" {
			fmt.Printf("A/B variant: %s\n", abVariant)
		}
		fmt.Printf("Request:\n%s\n", string(jsonBody))
		fmt.Printf("Response:\n%s\n", string(jsonResp))
		fmt.Println(strings.Repeat("-", 60))
	}
}

// GetLogs returns all logged requests.
func (s *HookServer) GetLogs() []RequestLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]RequestLog{}, s.logs...)
}

// ClearLogs clears all logged requests.
func (s *HookServer) ClearLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = make([]RequestLog, 0)
}

// =============================================================================
// Webhook Handlers (ServerInterface implementation)
// =============================================================================

// HealthCheck implements webhook.ServerInterface.
func (s *HookServer) HealthCheck(c *gin.Context) {
	cfg := s.cfgMgr.Get()
	status := server.HealthResponseStatus(cfg.Health.Status)
	resp := server.HealthResponse{Status: &status}

	s.logRequest("/health", nil, resp, "")
	c.JSON(http.StatusOK, resp)
}

// AccessHook implements webhook.ServerInterface.
func (s *HookServer) AccessHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}

	var req server.AccessHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  strPtr("INVALID_REQUEST"),
		})
		return
	}

	resp, ruleMatch := s.evaluateAccessRules(req)
	s.logRequest("/access", req, resp, ruleMatch)
	c.JSON(http.StatusOK, resp)
}

// PreHook implements webhook.ServerInterface.
func (s *HookServer) PreHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}

	var req server.PreHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  strPtr("INVALID_REQUEST"),
		})
		return
	}

	resp, ruleMatch, abVariant := s.evaluatePreRules(req)
	s.logRequestFull("/pre", req, resp, ruleMatch, false, abVariant)
	c.JSON(http.StatusOK, resp)
}

// PostHook implements webhook.ServerInterface.
func (s *HookServer) PostHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}

	var req server.PostHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  strPtr("INVALID_REQUEST"),
		})
		return
	}

	resp, ruleMatch, piiFound := s.evaluatePostRules(req)
	s.logRequestFull("/post", req, resp, ruleMatch, piiFound, "")
	c.JSON(http.StatusOK, resp)
}

// =============================================================================
// Access Hook Evaluation
// =============================================================================

func (s *HookServer) evaluateAccessRules(req server.AccessHookRequest) (*server.AccessHookResult, string) {
	cfg := s.cfgMgr.Get()
	accessCfg := cfg.Access

	allow := make(server.Toolkits)
	deny := make(server.Toolkits)
	ruleMatch := ""

	for toolkitName, toolkitInfo := range req.Toolkits {
		if toolkitInfo.Tools == nil {
			continue
		}
		for toolName, versions := range *toolkitInfo.Tools {
			action, matched := s.matchAccessRule(accessCfg, req.UserId, toolkitName, toolName)
			if matched != "" {
				ruleMatch = matched
			}

			if action == "deny" {
				if _, ok := deny[toolkitName]; !ok {
					deny[toolkitName] = server.ToolkitInfo{Tools: &map[string][]server.ToolVersionInfo{}}
				}
				(*deny[toolkitName].Tools)[toolName] = versions
			} else {
				if _, ok := allow[toolkitName]; !ok {
					allow[toolkitName] = server.ToolkitInfo{Tools: &map[string][]server.ToolVersionInfo{}}
				}
				(*allow[toolkitName].Tools)[toolName] = versions
			}
		}
	}

	result := &server.AccessHookResult{}
	if len(allow) > 0 {
		result.Only = &allow
	}
	if len(deny) > 0 {
		result.Deny = &deny
	}

	return result, ruleMatch
}

func (s *HookServer) matchAccessRule(cfg *AccessConfig, userID, toolkit, tool string) (string, string) {
	for i, rule := range cfg.Rules {
		if matchesPattern(rule.UserID, userID) &&
			matchesPattern(rule.Toolkit, toolkit) &&
			matchesPattern(rule.Tool, tool) {
			return rule.Action, fmt.Sprintf("access.rules[%d]", i)
		}
	}
	return cfg.DefaultAction, ""
}

// =============================================================================
// Pre-Hook Evaluation (with A/B testing)
// =============================================================================

func (s *HookServer) evaluatePreRules(req server.PreHookRequest) (*server.PreHookResult, string, string) {
	cfg := s.cfgMgr.Get()
	preCfg := cfg.Pre

	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// First evaluate basic rules
	for i, rule := range preCfg.Rules {
		if s.matchPreRule(rule, userID, req) {
			result := s.applyPreRule(rule)
			return result, fmt.Sprintf("pre.rules[%d]", i), ""
		}
	}

	// Check A/B testing - if enabled, may modify the request
	abVariant := ""
	if cfg.ABTesting != nil && cfg.ABTesting.Enabled && userID != "" {
		exp := s.abMgr.FindExperiment(req.Tool.Toolkit, req.Tool.Name, cfg.ABTesting.Experiments)
		if exp != nil {
			variant := s.abMgr.SelectVariant(userID, *exp)
			if variant != nil {
				abVariant = variant.Name
				result := &server.PreHookResult{Code: server.OK}
				override := &server.PreHookOverride{}
				hasOverride := false

				// Route to variant's server if specified
				if variant.Server != nil {
					override.Server = &server.ServerInfo{
						Name: variant.Server.Name,
						Uri:  variant.Server.URI,
						Type: server.ServerInfoType(variant.Server.Type),
					}
					hasOverride = true
				}

				if hasOverride {
					result.Override = override
				}
				return result, fmt.Sprintf("ab:%s->%s", exp.Name, variant.Name), abVariant
			}
		}
	}

	// Default action
	return &server.PreHookResult{
		Code: actionToCode(preCfg.DefaultAction),
	}, "", abVariant
}

func (s *HookServer) matchPreRule(rule PreRule, userID string, req server.PreHookRequest) bool {
	if !matchesPattern(rule.UserID, userID) {
		return false
	}
	if !matchesPattern(rule.Toolkit, req.Tool.Toolkit) {
		return false
	}
	if !matchesPattern(rule.Tool, req.Tool.Name) {
		return false
	}
	if !matchesPattern(rule.ExecutionID, req.ExecutionId) {
		return false
	}
	if rule.InputMatch != "" && !matchesInputs(rule.InputMatch, req.Inputs) {
		return false
	}
	return true
}

func (s *HookServer) applyPreRule(rule PreRule) *server.PreHookResult {
	result := &server.PreHookResult{
		Code: actionToCode(rule.Action),
	}

	if rule.ErrorMessage != "" {
		result.ErrorMessage = &rule.ErrorMessage
	}

	if rule.Override != nil && rule.Action == "proceed" {
		override := &server.PreHookOverride{}
		if len(rule.Override.Inputs) > 0 {
			override.Inputs = &rule.Override.Inputs
		}
		if len(rule.Override.Headers) > 0 {
			override.Headers = &rule.Override.Headers
		}
		if len(rule.Override.Secrets) > 0 {
			secrets := []map[string]string{rule.Override.Secrets}
			override.Secrets = &secrets
		}
		if rule.Override.Server != nil {
			override.Server = &server.ServerInfo{
				Name: rule.Override.Server.Name,
				Uri:  rule.Override.Server.URI,
				Type: server.ServerInfoType(rule.Override.Server.Type),
			}
		}
		result.Override = override
	}

	return result
}

// =============================================================================
// Post-Hook Evaluation (with PII redaction)
// =============================================================================

func (s *HookServer) evaluatePostRules(req server.PostHookRequest) (*server.PostHookResult, string, bool) {
	cfg := s.cfgMgr.Get()
	postCfg := cfg.Post

	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// First evaluate basic rules
	for i, rule := range postCfg.Rules {
		if s.matchPostRule(rule, userID, req) {
			result := s.applyPostRule(rule)
			return result, fmt.Sprintf("post.rules[%d]", i), false
		}
	}

	// Apply PII redaction if enabled
	piiFound := false
	if cfg.PII != nil && cfg.PII.Enabled && req.Output != nil {
		detector := NewPIIDetector(cfg.PII)
		scanResult := detector.ScanAndSummarize(req.Output)

		if scanResult.ContainsPII {
			piiFound = true

			if cfg.PII.Action == "block" {
				// Block the response entirely
				errMsg := "Response blocked: PII detected in output"
				return &server.PostHookResult{
					Code:         server.CHECKFAILED,
					ErrorMessage: &errMsg,
				}, "pii:block", true
			}

			// Redact PII from output
			redacted := detector.RedactMap(req.Output)
			return &server.PostHookResult{
				Code: server.OK,
				Override: &server.PostHookOverride{
					Output: &redacted,
				},
			}, "pii:redact", true
		}
	}

	// Default action
	return &server.PostHookResult{
		Code: actionToCode(postCfg.DefaultAction),
	}, "", piiFound
}

func (s *HookServer) matchPostRule(rule PostRule, userID string, req server.PostHookRequest) bool {
	if !matchesPattern(rule.UserID, userID) {
		return false
	}
	if !matchesPattern(rule.Toolkit, req.Tool.Toolkit) {
		return false
	}
	if !matchesPattern(rule.Tool, req.Tool.Name) {
		return false
	}
	if !matchesPattern(rule.ExecutionID, req.ExecutionId) {
		return false
	}
	if rule.Success != nil && req.Success != nil && *rule.Success != *req.Success {
		return false
	}
	if rule.OutputMatch != "" && !matchesInputs(rule.OutputMatch, req.Output) {
		return false
	}
	return true
}

func (s *HookServer) applyPostRule(rule PostRule) *server.PostHookResult {
	result := &server.PostHookResult{
		Code: actionToCode(rule.Action),
	}

	if rule.ErrorMessage != "" {
		result.ErrorMessage = &rule.ErrorMessage
	}

	if rule.Override != nil && rule.Action == "proceed" {
		if len(rule.Override.Output) > 0 {
			result.Override = &server.PostHookOverride{
				Output: &rule.Override.Output,
			}
		}
	}

	return result
}

// =============================================================================
// Admin/API Handlers
// =============================================================================

func (s *HookServer) handleGetConfig(c *gin.Context) {
	c.JSON(http.StatusOK, s.cfgMgr.Get())
}

func (s *HookServer) handleSetConfig(c *gin.Context) {
	var cfg Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.cfgMgr.Update(&cfg)

	// Save to file
	if err := s.cfgMgr.Save(); err != nil {
		log.Printf("Warning: failed to save config to file: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "configuration updated"})
}

func (s *HookServer) handleGetLogs(c *gin.Context) {
	logs := s.GetLogs()
	c.JSON(http.StatusOK, gin.H{
		"count": len(logs),
		"logs":  logs,
	})
}

func (s *HookServer) handleClearLogs(c *gin.Context) {
	s.ClearLogs()
	c.JSON(http.StatusOK, gin.H{"message": "logs cleared"})
}

func (s *HookServer) handleStatus(c *gin.Context) {
	cfg := s.cfgMgr.Get()
	c.JSON(http.StatusOK, gin.H{
		"status":       "running",
		"port":         s.serverCfg.Port,
		"auth_enabled": s.serverCfg.Token != "",
		"tls_enabled":  s.serverCfg.TLSEnabled,
		"mtls_enabled": s.serverCfg.TLSEnabled && s.serverCfg.CAFile != "",
		"config_file":  s.cfgMgr.ConfigPath(),
		"pii_enabled":  cfg.PII != nil && cfg.PII.Enabled,
		"ab_enabled":   cfg.ABTesting != nil && cfg.ABTesting.Enabled,
		"log_count":    len(s.GetLogs()),
	})
}

func (s *HookServer) handleFetchRegistryTools(c *gin.Context) {
	cfg := s.cfgMgr.Get()
	if cfg.ABTesting == nil || cfg.ABTesting.ToolRegistry == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tool registry not configured"})
		return
	}

	result, err := FetchToolsFromRegistry(cfg.ABTesting.ToolRegistry)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *HookServer) handleGetABStats(c *gin.Context) {
	c.JSON(http.StatusOK, s.abMgr.GetStats())
}

func (s *HookServer) handleResetABStats(c *gin.Context) {
	s.abMgr.ResetStats()
	c.JSON(http.StatusOK, gin.H{"message": "A/B testing stats and assignments reset"})
}

func (s *HookServer) handleSaveConfig(c *gin.Context) {
	if err := s.cfgMgr.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "configuration saved to " + s.cfgMgr.ConfigPath()})
}

func (s *HookServer) handleTestPII(c *gin.Context) {
	var body struct {
		Text string `json:"text"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := s.cfgMgr.Get()
	detector := NewPIIDetector(cfg.PII)

	data := map[string]interface{}{"text": body.Text}
	result := detector.ScanAndSummarize(data)
	redacted := detector.RedactString(body.Text)

	c.JSON(http.StatusOK, gin.H{
		"original":  body.Text,
		"redacted":  redacted,
		"scan":      result,
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func (s *HookServer) validateAuth(c *gin.Context) bool {
	if s.serverCfg.Token == "" {
		return true
	}

	auth := c.GetHeader("Authorization")
	expected := "Bearer " + s.serverCfg.Token
	if auth != expected {
		c.JSON(http.StatusUnauthorized, server.ErrorResponse{
			Error: strPtr("invalid or missing bearer token"),
			Code:  strPtr("UNAUTHORIZED"),
		})
		return false
	}
	return true
}

func matchesPattern(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "~") {
		re, err := regexp.Compile(pattern[1:])
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	if strings.Contains(pattern, "*") {
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return pattern == value
}

// matchesGlob is like matchesPattern but treats empty as non-matching
// (used for A/B test experiment matching where both toolkit and tool must be specified).
func matchesGlob(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	return matchesPattern(pattern, value)
}

func matchesInputs(expr string, inputs map[string]interface{}) bool {
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		if len(parts) != 2 {
			return false
		}
		key, substring := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if val, ok := inputs[key]; ok {
			return strings.Contains(fmt.Sprintf("%v", val), substring)
		}
		return false
	}
	if strings.Contains(expr, "=") {
		parts := strings.SplitN(expr, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key, expected := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if val, ok := inputs[key]; ok {
			return fmt.Sprintf("%v", val) == expected
		}
		return false
	}
	_, ok := inputs[expr]
	return ok
}

func actionToCode(action string) server.ResponseCode {
	switch action {
	case "proceed", "allow", "":
		return server.OK
	case "block", "deny":
		return server.CHECKFAILED
	case "rate_limit":
		return server.RATELIMITEXCEEDED
	default:
		return server.OK
	}
}

func strPtr(s string) *string {
	return &s
}

// =============================================================================
// Config File Watching
// =============================================================================

func watchConfigFile(path string, cfgMgr *ConfigManager) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		log.Printf("Failed to watch config file: %v", err)
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file changed, reloading...")
				if err := cfgMgr.Load(); err != nil {
					log.Printf("Warning: failed to reload config: %v", err)
				} else {
					log.Printf("Configuration reloaded successfully")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		case <-sigChan:
			return
		}
	}
}

// =============================================================================
// TLS Configuration
// =============================================================================

func buildTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// =============================================================================
// Banner
// =============================================================================

func printBanner(cfg *ServerConfig) {
	protocol := "http"
	if cfg.TLSEnabled {
		protocol = "https"
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Hook Server (Advanced)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Port:        %d\n", cfg.Port)
	fmt.Printf("  Auth:        %s\n", authStatus(cfg.Token))
	fmt.Printf("  TLS:         %s\n", tlsStatus(cfg))
	fmt.Printf("  Config:      %s\n", configStatus(cfg.ConfigFile))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("Dashboard:")
	fmt.Printf("  %s://localhost:%d/\n", protocol, cfg.Port)
	fmt.Println()
	fmt.Println("Webhook Endpoints:")
	fmt.Printf("  GET  %s://localhost:%d/health\n", protocol, cfg.Port)
	fmt.Printf("  POST %s://localhost:%d/access\n", protocol, cfg.Port)
	fmt.Printf("  POST %s://localhost:%d/pre\n", protocol, cfg.Port)
	fmt.Printf("  POST %s://localhost:%d/post\n", protocol, cfg.Port)
	fmt.Println()
	fmt.Println("API Endpoints:")
	fmt.Printf("  GET/PUT  %s://localhost:%d/api/config\n", protocol, cfg.Port)
	fmt.Printf("  GET/DEL  %s://localhost:%d/api/logs\n", protocol, cfg.Port)
	fmt.Printf("  GET      %s://localhost:%d/api/status\n", protocol, cfg.Port)
	fmt.Printf("  POST     %s://localhost:%d/api/registry/fetch\n", protocol, cfg.Port)
	fmt.Printf("  GET      %s://localhost:%d/api/ab/stats\n", protocol, cfg.Port)
	fmt.Printf("  POST     %s://localhost:%d/api/pii/test\n", protocol, cfg.Port)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Ready to receive requests...")
	fmt.Println()
}

func authStatus(token string) string {
	if token == "" {
		return "disabled"
	}
	return fmt.Sprintf("enabled (token: %s...)", token[:min(8, len(token))])
}

func tlsStatus(cfg *ServerConfig) string {
	if !cfg.TLSEnabled {
		return "disabled (HTTP)"
	}
	if cfg.CAFile != "" {
		return "mTLS enabled (client cert required)"
	}
	return "TLS enabled (HTTPS)"
}

func configStatus(path string) string {
	if path == "" {
		return "none (using defaults)"
	}
	return path + " (hot-reload enabled)"
}

// =============================================================================
// Main
// =============================================================================

func main() {
	serverCfg := &ServerConfig{}
	defaultConfigPath := "hook-config.yaml"

	flag.IntVar(&serverCfg.Port, "port", 8888, "Port to listen on")
	flag.StringVar(&serverCfg.Token, "token", "", "Bearer token for authentication (empty = no auth)")
	flag.BoolVar(&serverCfg.Verbose, "verbose", true, "Log all requests to stdout")
	flag.StringVar(&serverCfg.ConfigFile, "config", "", "Path to YAML configuration file")

	// TLS flags
	flag.BoolVar(&serverCfg.TLSEnabled, "tls", false, "Enable TLS/HTTPS")
	flag.StringVar(&serverCfg.CertFile, "cert", "", "Path to server certificate (PEM)")
	flag.StringVar(&serverCfg.KeyFile, "key", "", "Path to server private key (PEM)")
	flag.StringVar(&serverCfg.CAFile, "ca", "", "Path to CA certificate for client verification (mTLS)")
	flag.Parse()

	if serverCfg.TLSEnabled && (serverCfg.CertFile == "" || serverCfg.KeyFile == "") {
		log.Fatal("TLS enabled but -cert and -key are required")
	}

	// Determine config file path
	configPath := serverCfg.ConfigFile
	if configPath == "" {
		configPath = defaultConfigPath
	}

	cfgMgr := NewConfigManager(configPath)

	// Try to load existing config
	if serverCfg.ConfigFile != "" {
		if err := cfgMgr.Load(); err != nil {
			log.Printf("Warning: failed to load config from %s: %v", configPath, err)
		} else {
			log.Printf("Loaded configuration from %s", configPath)
		}
	} else if _, err := os.Stat(defaultConfigPath); err == nil {
		if err := cfgMgr.Load(); err != nil {
			log.Printf("Warning: failed to load default config: %v", err)
		} else {
			log.Printf("Loaded configuration from %s", defaultConfigPath)
		}
	} else {
		// Save default config to file
		if err := cfgMgr.Save(); err != nil {
			log.Printf("Warning: failed to save default config: %v", err)
		} else {
			log.Printf("Created default configuration at %s", configPath)
		}
	}

	// Watch config file for changes
	go watchConfigFile(configPath, cfgMgr)

	srv := NewHookServer(serverCfg, cfgMgr)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Dashboard UI
	router.GET("/", srv.serveDashboard)

	// Webhook endpoints (from generated ServerInterface)
	server.RegisterHandlers(router, srv)

	// API endpoints
	api := router.Group("/api")
	{
		api.GET("/config", srv.handleGetConfig)
		api.PUT("/config", srv.handleSetConfig)
		api.POST("/config", srv.handleSetConfig)
		api.POST("/config/save", srv.handleSaveConfig)

		api.GET("/logs", srv.handleGetLogs)
		api.DELETE("/logs", srv.handleClearLogs)

		api.GET("/status", srv.handleStatus)

		api.POST("/registry/fetch", srv.handleFetchRegistryTools)

		api.GET("/ab/stats", srv.handleGetABStats)
		api.DELETE("/ab/stats", srv.handleResetABStats)

		api.POST("/pii/test", srv.handleTestPII)
	}

	printBanner(serverCfg)

	addr := fmt.Sprintf(":%d", serverCfg.Port)

	if serverCfg.TLSEnabled {
		tlsConfig, err := buildTLSConfig(serverCfg)
		if err != nil {
			log.Fatal("Failed to configure TLS:", err)
		}

		httpServer := &http.Server{
			Addr:      addr,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		if err := httpServer.ListenAndServeTLS(serverCfg.CertFile, serverCfg.KeyFile); err != nil {
			log.Fatal("Failed to start TLS server:", err)
		}
	} else {
		if err := router.Run(addr); err != nil {
			log.Fatal("Failed to start server:", err)
		}
	}
}

// ensureConfigFile creates a config file with provided config if it doesn't exist.
func ensureConfigFile(path string, cfg *Config) error {
	if _, err := os.Stat(path); err == nil {
		return nil // File exists
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
