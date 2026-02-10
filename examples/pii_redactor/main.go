// pii_redactor is a minimal CATE webhook server that demonstrates how to
// detect and redact personally identifiable information (PII) from tool outputs.
//
// It uses the post-execution hook to scan tool responses and replace PII with
// redaction markers before the data reaches the agent.
//
// Supported PII types: email, IP address, SSN, phone number, credit card, date of birth.
//
// Usage:
//
//	go run ./examples/pii_redactor -port 8889
//	go run ./examples/pii_redactor -port 8889 -mode block   # Block instead of redact
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

// PIIType represents a type of PII to detect.
type PIIType struct {
	Name        string
	Pattern     *regexp.Regexp
	Replacement string
	Enabled     bool
}

// PIIRedactor detects and redacts PII from text and structured data.
type PIIRedactor struct {
	types []*PIIType
	mode  string // "redact" or "block"
}

// NewPIIRedactor creates a redactor with all standard PII types enabled.
func NewPIIRedactor(mode string) *PIIRedactor {
	// Order matters: credit_card must be matched before phone_number
	// to avoid partial matches on credit card digits.
	return &PIIRedactor{
		mode: mode,
		types: []*PIIType{
			{
				Name:        "email",
				Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
				Replacement: "[EMAIL_REDACTED]",
				Enabled:     true,
			},
			{
				Name:        "ip_address",
				Pattern:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
				Replacement: "[IP_REDACTED]",
				Enabled:     true,
			},
			{
				Name:        "credit_card",
				Pattern:     regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
				Replacement: "[CC_REDACTED]",
				Enabled:     true,
			},
			{
				Name:        "ssn",
				Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
				Replacement: "[SSN_REDACTED]",
				Enabled:     true,
			},
			{
				Name:        "phone_number",
				Pattern:     regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
				Replacement: "[PHONE_REDACTED]",
				Enabled:     true,
			},
			{
				Name:        "date_of_birth",
				Pattern:     regexp.MustCompile(`\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b`),
				Replacement: "[DOB_REDACTED]",
				Enabled:     true,
			},
		},
	}
}

// RedactText scans text for PII and replaces it with redaction markers.
func (r *PIIRedactor) RedactText(text string) (string, int) {
	result := text
	count := 0
	for _, t := range r.types {
		if !t.Enabled {
			continue
		}
		matches := t.Pattern.FindAllString(result, -1)
		count += len(matches)
		result = t.Pattern.ReplaceAllString(result, t.Replacement)
	}
	return result, count
}

// ContainsPII checks if text contains any PII.
func (r *PIIRedactor) ContainsPII(text string) bool {
	for _, t := range r.types {
		if !t.Enabled {
			continue
		}
		if t.Pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// RedactMap recursively scans a map and redacts PII from all string values.
func (r *PIIRedactor) RedactMap(data map[string]interface{}) (map[string]interface{}, int) {
	totalCount := 0
	result := make(map[string]interface{}, len(data))
	for k, v := range data {
		redacted, count := r.redactValue(v)
		result[k] = redacted
		totalCount += count
	}
	return result, totalCount
}

func (r *PIIRedactor) redactValue(v interface{}) (interface{}, int) {
	switch val := v.(type) {
	case string:
		redacted, count := r.RedactText(val)
		return redacted, count
	case map[string]interface{}:
		return r.RedactMap(val)
	case []interface{}:
		total := 0
		result := make([]interface{}, len(val))
		for i, item := range val {
			redacted, count := r.redactValue(item)
			result[i] = redacted
			total += count
		}
		return result, total
	default:
		return v, 0
	}
}

// CheckMapForPII checks if any value in a map contains PII.
func (r *PIIRedactor) CheckMapForPII(data map[string]interface{}) bool {
	for _, v := range data {
		if r.checkValue(v) {
			return true
		}
	}
	return false
}

func (r *PIIRedactor) checkValue(v interface{}) bool {
	switch val := v.(type) {
	case string:
		return r.ContainsPII(val)
	case map[string]interface{}:
		return r.CheckMapForPII(val)
	case []interface{}:
		for _, item := range val {
			if r.checkValue(item) {
				return true
			}
		}
	}
	return false
}

// =============================================================================
// PII Redactor Server
// =============================================================================

// RedactorServer implements the CATE webhook ServerInterface.
type RedactorServer struct {
	redactor *PIIRedactor
}

// HealthCheck implements webhook.ServerInterface.
func (s *RedactorServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook passes through - PII redaction doesn't affect tool visibility.
func (s *RedactorServer) AccessHook(c *gin.Context) {
	// Allow all tools - PII redaction only applies to outputs
	c.JSON(http.StatusOK, server.AccessHookResult{})
}

// PreHook passes through - PII redaction only applies to outputs.
func (s *RedactorServer) PreHook(c *gin.Context) {
	// Allow all requests to proceed
	c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
}

// PostHook scans tool output for PII and redacts or blocks it.
// This is where the PII redaction happens - after the tool executes,
// before the response reaches the agent.
func (s *RedactorServer) PostHook(c *gin.Context) {
	var req server.PostHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request: " + err.Error()),
		})
		return
	}

	if s.redactor.mode == "block" {
		// Block mode: reject the entire response if PII is found
		if s.redactor.CheckMapForPII(req.Output) {
			msg := "Response blocked: contains personally identifiable information"
			log.Printf("[POST] Blocked PII in output from %s.%s",
				req.Tool.Toolkit, req.Tool.Name)
			c.JSON(http.StatusOK, server.PostHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &msg,
			})
			return
		}
	} else {
		// Redact mode: replace PII with placeholders
		redactedOutput, count := s.redactor.RedactMap(req.Output)
		if count > 0 {
			log.Printf("[POST] Redacted %d PII instances in output from %s.%s",
				count, req.Tool.Toolkit, req.Tool.Name)
			c.JSON(http.StatusOK, server.PostHookResult{
				Code: server.OK,
				Override: &server.PostHookOverride{
					Output: &redactedOutput,
				},
			})
			return
		}
	}

	// No PII found, pass through
	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

func strPtr(s string) *string {
	return &s
}

// =============================================================================
// Main
// =============================================================================

func main() {
	port := flag.Int("port", 8889, "Port to listen on")
	mode := flag.String("mode", "redact", "PII handling mode: 'redact' or 'block'")
	flag.Parse()

	redactor := NewPIIRedactor(*mode)
	srv := &RedactorServer{redactor: redactor}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	server.RegisterHandlers(router, srv)

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("  PII Redactor Example")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  Port: %d\n", *port)
	fmt.Printf("  Mode: %s\n", *mode)
	fmt.Println()
	fmt.Println("  This example demonstrates:")
	fmt.Println("  - Detecting PII in tool outputs (post-hook)")
	if *mode == "redact" {
		fmt.Println("  - Replacing PII with redaction markers")
	} else {
		fmt.Println("  - Blocking responses that contain PII")
	}
	fmt.Println()
	fmt.Println("  Detected PII types:")
	fmt.Println("  - Email addresses    -> [EMAIL_REDACTED]")
	fmt.Println("  - IP addresses       -> [IP_REDACTED]")
	fmt.Println("  - SSN                -> [SSN_REDACTED]")
	fmt.Println("  - Phone numbers      -> [PHONE_REDACTED]")
	fmt.Println("  - Credit card numbers-> [CC_REDACTED]")
	fmt.Println("  - Dates of birth     -> [DOB_REDACTED]")
	fmt.Println(strings.Repeat("=", 50))

	addr := fmt.Sprintf(":%d", *port)
	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
