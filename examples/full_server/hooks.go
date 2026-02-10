package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// Request Logging
// =============================================================================

// RequestLog stores information about each incoming request.
type RequestLog struct {
	Timestamp  time.Time   `json:"timestamp"`
	Endpoint   string      `json:"endpoint"`
	Body       interface{} `json:"body"`
	Response   interface{} `json:"response"`
	RuleMatch  string      `json:"rule_match,omitempty"`
	PIIFound   []PIIMatch  `json:"pii_found,omitempty"`
	ABVariant  string      `json:"ab_variant,omitempty"`
}

// =============================================================================
// Hook Server
// =============================================================================

// HookServer implements the webhook ServerInterface with all features.
type HookServer struct {
	mu          sync.RWMutex
	logs        []RequestLog
	cfgMgr      *ConfigManager
	piiDetector *PIIDetector
	abEngine    *ABTestingEngine
	arcadeClient *ArcadeClient
	verbose     bool
	token       string
}

// NewHookServer creates a new hook server with all subsystems.
func NewHookServer(cfgMgr *ConfigManager, token string, verbose bool) *HookServer {
	return &HookServer{
		logs:         make([]RequestLog, 0),
		cfgMgr:       cfgMgr,
		piiDetector:  NewPIIDetector(),
		abEngine:     NewABTestingEngine(),
		arcadeClient: NewArcadeClient(),
		verbose:      verbose,
		token:        token,
	}
}

func (s *HookServer) logRequest(endpoint string, body, response interface{}, ruleMatch string, piiFound []PIIMatch, abVariant string) {
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

	if s.verbose {
		jsonBody, _ := json.MarshalIndent(body, "", "  ")
		jsonResp, _ := json.MarshalIndent(response, "", "  ")
		fmt.Printf("\n[%s] %s\n", time.Now().Format("15:04:05"), endpoint)
		if ruleMatch != "" {
			fmt.Printf("  Rule matched: %s\n", ruleMatch)
		}
		if abVariant != "" {
			fmt.Printf("  A/B Variant: %s\n", abVariant)
		}
		if len(piiFound) > 0 {
			fmt.Printf("  PII detected: %d instances\n", len(piiFound))
		}
		fmt.Printf("  Request: %s\n", string(jsonBody))
		fmt.Printf("  Response: %s\n", string(jsonResp))
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
// Auth
// =============================================================================

func (s *HookServer) validateAuth(c *gin.Context) bool {
	if s.token == "" {
		return true
	}

	auth := c.GetHeader("Authorization")
	expected := "Bearer " + s.token
	if auth != expected {
		c.JSON(http.StatusUnauthorized, server.ErrorResponse{
			Error: strPtr("invalid or missing bearer token"),
			Code:  strPtr("UNAUTHORIZED"),
		})
		return false
	}
	return true
}

// =============================================================================
// Health Check
// =============================================================================

// HealthCheck implements webhook.ServerInterface.
func (s *HookServer) HealthCheck(c *gin.Context) {
	cfg := s.cfgMgr.Get()
	status := server.HealthResponseStatus(cfg.Health.Status)
	resp := server.HealthResponse{Status: &status}
	s.logRequest("/health", nil, resp, "", nil, "")
	c.JSON(http.StatusOK, resp)
}

// =============================================================================
// Access Hook
// =============================================================================

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
	s.logRequest("/access", req, resp, ruleMatch, nil, "")
	c.JSON(http.StatusOK, resp)
}

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
			action, matchedRule := s.matchAccessRule(accessCfg, req.UserId, toolkitName, toolName)
			if matchedRule != "" {
				ruleMatch = matchedRule
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
		if matchesGlob(rule.UserID, userID) &&
			matchesGlob(rule.ToolkitMatch, toolkit) &&
			matchesGlob(rule.ToolMatch, tool) {
			return rule.Action, fmt.Sprintf("access.rules[%d]", i)
		}
	}
	return cfg.DefaultAction, ""
}

// =============================================================================
// Pre-Execution Hook
// =============================================================================

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

	cfg := s.cfgMgr.Get()
	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// 1. Check PII in inputs (if configured for pre-hook blocking)
	if cfg.PII != nil && cfg.PII.Enabled && cfg.PII.Mode == "block" {
		if s.piiDetector.CheckMapForPII(req.Inputs, cfg.PII) {
			matches := s.piiDetector.DetectPII(fmt.Sprintf("%v", req.Inputs), cfg.PII)
			resp := &server.PreHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: strPtr("Request contains PII data that is not allowed"),
			}
			s.logRequest("/pre", req, resp, "pii_block", matches, "")
			c.JSON(http.StatusOK, resp)
			return
		}
	}

	// 2. Evaluate pre-execution rules
	resp, ruleMatch := s.evaluatePreRules(req, userID)

	// 3. Check A/B testing (may override server routing)
	abVariant := ""
	if cfg.ABTesting != nil && cfg.ABTesting.Enabled && resp.Code == server.OK {
		experiment := s.abEngine.FindExperiment(cfg.ABTesting, req.Tool.Toolkit, req.Tool.Name)
		if experiment != nil {
			variant := s.abEngine.AssignVariant(experiment, userID)
			if variant != nil && variant.Server != nil {
				abVariant = fmt.Sprintf("%s/%s", experiment.Name, variant.Name)
				if resp.Override == nil {
					resp.Override = &server.PreHookOverride{}
				}
				resp.Override.Server = &server.ServerInfo{
					Name: variant.Server.Name,
					Uri:  variant.Server.URI,
					Type: server.ServerInfoType(variant.Server.Type),
				}
			}
		}
	}

	s.logRequest("/pre", req, resp, ruleMatch, nil, abVariant)
	c.JSON(http.StatusOK, resp)
}

func (s *HookServer) evaluatePreRules(req server.PreHookRequest, userID string) (*server.PreHookResult, string) {
	cfg := s.cfgMgr.Get()
	preCfg := cfg.Pre

	for i, rule := range preCfg.Rules {
		if s.matchPreRule(rule, userID, req) {
			result := s.applyPreRule(rule)
			return result, fmt.Sprintf("pre.rules[%d]", i)
		}
	}

	return &server.PreHookResult{
		Code: actionToCode(preCfg.DefaultAction),
	}, ""
}

func (s *HookServer) matchPreRule(rule PreRule, userID string, req server.PreHookRequest) bool {
	if !matchesGlob(rule.UserID, userID) {
		return false
	}
	if !matchesGlob(rule.Toolkit, req.Tool.Toolkit) {
		return false
	}
	if !matchesGlob(rule.Tool, req.Tool.Name) {
		return false
	}
	if !matchesGlob(rule.ExecutionID, req.ExecutionId) {
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
// Post-Execution Hook
// =============================================================================

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

	cfg := s.cfgMgr.Get()
	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// 1. Evaluate post-execution rules
	resp, ruleMatch := s.evaluatePostRules(req, userID)

	// 2. Apply PII redaction on output (if enabled and not already blocked)
	var piiFound []PIIMatch
	if cfg.PII != nil && cfg.PII.Enabled && resp.Code == server.OK {
		if cfg.PII.Mode == "redact" {
			redactedOutput, matches := s.piiDetector.RedactMap(req.Output, cfg.PII)
			if len(matches) > 0 {
				piiFound = matches
				if resp.Override == nil {
					resp.Override = &server.PostHookOverride{}
				}
				resp.Override.Output = &redactedOutput
			}
		} else if cfg.PII.Mode == "block" {
			if s.piiDetector.CheckMapForPII(req.Output, cfg.PII) {
				matches := s.piiDetector.DetectPII(fmt.Sprintf("%v", req.Output), cfg.PII)
				piiFound = matches
				resp = &server.PostHookResult{
					Code:         server.CHECKFAILED,
					ErrorMessage: strPtr("Response contains PII data that has been blocked"),
				}
			}
		}
	}

	s.logRequest("/post", req, resp, ruleMatch, piiFound, "")
	c.JSON(http.StatusOK, resp)
}

func (s *HookServer) evaluatePostRules(req server.PostHookRequest, userID string) (*server.PostHookResult, string) {
	cfg := s.cfgMgr.Get()
	postCfg := cfg.Post

	for i, rule := range postCfg.Rules {
		if s.matchPostRule(rule, userID, req) {
			result := s.applyPostRule(rule)
			return result, fmt.Sprintf("post.rules[%d]", i)
		}
	}

	return &server.PostHookResult{
		Code: actionToCode(postCfg.DefaultAction),
	}, ""
}

func (s *HookServer) matchPostRule(rule PostRule, userID string, req server.PostHookRequest) bool {
	if !matchesGlob(rule.UserID, userID) {
		return false
	}
	if !matchesGlob(rule.Toolkit, req.Tool.Toolkit) {
		return false
	}
	if !matchesGlob(rule.Tool, req.Tool.Name) {
		return false
	}
	if !matchesGlob(rule.ExecutionID, req.ExecutionId) {
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
// Helpers
// =============================================================================

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
		// Also check the full stringified map for general content matching
		fullStr := fmt.Sprintf("%v", inputs)
		return strings.Contains(fullStr, substring)
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
	// Just check if key exists
	_, ok := inputs[expr]
	return ok
}

func strPtr(s string) *string {
	return &s
}
