// pii_redactor demonstrates how to detect and redact PII from tool outputs.
//
// This minimal hook server shows:
//   - Scanning tool outputs and content text blocks for PII (emails, IPs, SSNs, phone numbers, etc.)
//   - Replacing detected PII with labeled placeholders
//   - Optionally blocking responses that contain PII instead of redacting
//
// Usage:
//
//	go run ./examples/contextual_access/pii_redactor -port 8888
//	go run ./examples/contextual_access/pii_redactor -port 8888 -action block
//	go run ./examples/contextual_access/pii_redactor -port 8888 -types "email,ssn,credit_card"
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// PII Detection
// =============================================================================

// PIIPattern defines a PII type with its detection regex.
type PIIPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Replacement string
}

// AllPIIPatterns returns all available PII detection patterns.
func AllPIIPatterns() map[string]PIIPattern {
	return map[string]PIIPattern{
		"email": {
			Name:        "email",
			Regex:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Replacement: "[EMAIL REDACTED]",
		},
		"ipv4": {
			Name:        "ipv4",
			Regex:       regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			Replacement: "[IP REDACTED]",
		},
		"ssn": {
			Name:        "ssn",
			Regex:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Replacement: "[SSN REDACTED]",
		},
		"phone": {
			Name:        "phone",
			Regex:       regexp.MustCompile(`(?:\+?\b1[-.\s]?\(?|\(|\b)\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			Replacement: "[PHONE REDACTED]",
		},
		"credit_card": {
			Name:        "credit_card",
			Regex:       regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
			Replacement: "[CREDIT CARD REDACTED]",
		},
		"date_of_birth": {
			Name:        "date_of_birth",
			Regex:       regexp.MustCompile(`\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b`),
			Replacement: "[DOB REDACTED]",
		},
	}
}

// =============================================================================
// Server
// =============================================================================

// RedactorServer implements the webhook ServerInterface.
type RedactorServer struct {
	token    string
	action   string       // "redact" or "block"
	patterns []PIIPattern // active patterns
}

func NewRedactorServer(token, action string, enabledTypes []string) *RedactorServer {
	allPatterns := AllPIIPatterns()
	var active []PIIPattern

	for _, t := range enabledTypes {
		if p, ok := allPatterns[t]; ok {
			active = append(active, p)
		} else {
			log.Printf("Warning: unknown PII type %q", t)
		}
	}

	return &RedactorServer{
		token:    token,
		action:   action,
		patterns: active,
	}
}

// HealthCheck implements ServerInterface.
func (s *RedactorServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook implements ServerInterface. Pass-through.
func (s *RedactorServer) AccessHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}
	var req server.AccessHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  responseCodePtr(server.CHECKFAILED),
		})
		return
	}
	// Pass-through: PII redaction doesn't affect tool visibility
	c.JSON(http.StatusOK, server.AccessHookResult{})
}

// PreHook implements ServerInterface. Pass-through.
func (s *RedactorServer) PreHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}
	var req server.PreHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  responseCodePtr(server.CHECKFAILED),
		})
		return
	}
	// Pass-through: PII redaction only applies to outputs
	c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
}

// PostHook implements ServerInterface.
// This is where PII detection and redaction happens.
func (s *RedactorServer) PostHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}

	var req server.PostHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  responseCodePtr(server.CHECKFAILED),
		})
		return
	}

	// Scan all output values for PII, and the content text blocks a remote
	// server sent alongside them: clients see those too, so both must be redacted.
	piiFound := s.scanValue(req.Output)
	if req.Content != nil {
		piiFound = append(piiFound, s.scanContent(*req.Content)...)
	}
	if len(piiFound) == 0 {
		// No PII detected - pass through
		c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
		return
	}

	// Log what was found
	log.Printf("[POST] PII detected in %s.%s result:", req.Tool.Toolkit, req.Tool.Name)
	for _, match := range piiFound {
		log.Printf("  - %s: %q", match.typeName, match.value)
	}

	if s.action == "block" {
		// Block the entire response
		errMsg := fmt.Sprintf("Response blocked: %d PII item(s) detected (%s)",
			len(piiFound), summarizeTypes(piiFound))
		log.Printf("[POST] Blocking response: %s", errMsg)
		c.JSON(http.StatusOK, server.PostHookResult{
			Code:         server.CHECKFAILED,
			ErrorMessage: &errMsg,
		})
		return
	}

	// Redact PII in the output and content text blocks
	override := &server.PostHookOverride{Output: s.redactValue(req.Output)}
	if req.Content != nil {
		content := s.redactContent(*req.Content)
		override.Content = &content
	}
	log.Printf("[POST] Redacted %d PII item(s) in result", len(piiFound))
	c.JSON(http.StatusOK, server.PostHookResult{
		Code:     server.OK,
		Override: override,
	})
}

// =============================================================================
// PII Scanning and Redaction
// =============================================================================

type piiMatch struct {
	typeName string
	value    string
}

// scanMap recursively scans all string values in a map for PII.
func (s *RedactorServer) scanMap(m map[string]interface{}) []piiMatch {
	var matches []piiMatch
	for _, v := range m {
		matches = append(matches, s.scanValue(v)...)
	}
	return matches
}

func (s *RedactorServer) scanValue(v interface{}) []piiMatch {
	var matches []piiMatch
	switch val := v.(type) {
	case string:
		for _, p := range s.patterns {
			found := p.Regex.FindAllString(val, -1)
			for _, f := range found {
				matches = append(matches, piiMatch{typeName: p.Name, value: f})
			}
		}
	case map[string]interface{}:
		matches = append(matches, s.scanMap(val)...)
	case []interface{}:
		for _, item := range val {
			matches = append(matches, s.scanValue(item)...)
		}
	}
	return matches
}

// redactMap recursively redacts PII in all string values of a map.
func (s *RedactorServer) redactMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = s.redactValue(v)
	}
	return result
}

func (s *RedactorServer) redactValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		result := val
		for _, p := range s.patterns {
			result = p.Regex.ReplaceAllString(result, p.Replacement)
		}
		return result
	case map[string]interface{}:
		return s.redactMap(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = s.redactValue(item)
		}
		return result
	default:
		return v
	}
}

// scanContent scans text blocks for PII. Other block types pass through
// unscanned; extend this if your servers put text there.
func (s *RedactorServer) scanContent(blocks []server.ContentBlock) []piiMatch {
	var matches []piiMatch
	for _, b := range blocks {
		if b.Type == "text" {
			matches = append(matches, s.scanMap(b.AdditionalProperties)...)
		}
	}
	return matches
}

// redactContent redacts PII in text blocks and passes other blocks through
// unchanged.
func (s *RedactorServer) redactContent(blocks []server.ContentBlock) []server.ContentBlock {
	result := make([]server.ContentBlock, len(blocks))
	for i, b := range blocks {
		result[i] = b
		if b.Type == "text" {
			result[i].AdditionalProperties = s.redactMap(b.AdditionalProperties)
		}
	}
	return result
}

// =============================================================================
// Helpers
// =============================================================================

func (s *RedactorServer) validateAuth(c *gin.Context) bool {
	if s.token == "" {
		return true
	}
	auth := c.GetHeader("Authorization")
	if auth != "Bearer "+s.token {
		c.JSON(http.StatusUnauthorized, server.ErrorResponse{
			Error: strPtr("invalid or missing bearer token"),
			Code:  responseCodePtr(server.CHECKFAILED),
		})
		return false
	}
	return true
}

func summarizeTypes(matches []piiMatch) string {
	seen := make(map[string]bool)
	var types []string
	for _, m := range matches {
		if !seen[m.typeName] {
			seen[m.typeName] = true
			types = append(types, m.typeName)
		}
	}
	return strings.Join(types, ", ")
}

func strPtr(s string) *string { return &s }

func responseCodePtr(c server.ResponseCode) *server.ResponseCode { return &c }

// =============================================================================
// Main
// =============================================================================

func main() {
	var (
		port   int
		token  string
		action string
		types  string
	)

	flag.IntVar(&port, "port", 8888, "Port to listen on")
	flag.StringVar(&token, "token", "", "Bearer token for authentication")
	flag.StringVar(&action, "action", "redact", "Action when PII found: 'redact' or 'block'")
	flag.StringVar(&types, "types", "email,ipv4,ssn,phone,credit_card,date_of_birth", "Comma-separated PII types to detect")
	flag.Parse()

	enabledTypes := strings.Split(types, ",")
	for i := range enabledTypes {
		enabledTypes[i] = strings.TrimSpace(enabledTypes[i])
	}

	srv := NewRedactorServer(token, action, enabledTypes)

	fmt.Printf("\nPII Redactor Hook Server\n")
	fmt.Printf("  Action: %s\n", action)
	fmt.Printf("  PII types: %s\n", strings.Join(enabledTypes, ", "))
	fmt.Println()

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	server.RegisterHandlers(router, srv)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Listening on %s\n", addr)
	fmt.Printf("  POST /post - Scan and redact PII from tool outputs and content text blocks\n\n")

	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
