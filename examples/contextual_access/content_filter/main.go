// content_filter demonstrates how to block or modify tool calls based on their content.
//
// This minimal hook server shows:
//   - Blocking tool execution based on input content (pre-hook)
//   - Blocking or replacing tool output and content text blocks based on content (post-hook)
//   - Using keyword lists and pattern matching for content filtering
//
// Usage:
//
//	go run ./examples/contextual_access/content_filter -port 8888
//	go run ./examples/contextual_access/content_filter -port 8888 -config ./examples/contextual_access/content_filter/example-config.yaml
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// Config defines content filtering rules.
type Config struct {
	// BlockedKeywords are blocked in both inputs and outputs
	BlockedKeywords []string `yaml:"blocked_keywords" json:"blocked_keywords"`

	// BlockedInputPatterns are regex patterns that block tool execution when found in inputs
	BlockedInputPatterns []PatternRule `yaml:"blocked_input_patterns" json:"blocked_input_patterns"`

	// BlockedOutputPatterns are regex patterns that block or replace content in outputs
	BlockedOutputPatterns []PatternRule `yaml:"blocked_output_patterns" json:"blocked_output_patterns"`

	// BlockedToolkits are toolkit names that are entirely blocked
	BlockedToolkits []string `yaml:"blocked_toolkits" json:"blocked_toolkits"`
}

// PatternRule defines a regex pattern with an action.
type PatternRule struct {
	Name        string `yaml:"name" json:"name"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Action      string `yaml:"action" json:"action"` // "block" or "replace"
	Replacement string `yaml:"replacement" json:"replacement"`
	Message     string `yaml:"message" json:"message"` // error message when blocking
}

// FilterServer implements the webhook ServerInterface.
type FilterServer struct {
	config          *Config
	token           string
	compiledInputs  []*compiledPattern
	compiledOutputs []*compiledPattern
}

type compiledPattern struct {
	rule    PatternRule
	pattern *regexp.Regexp
}

func NewFilterServer(cfg *Config, token string) *FilterServer {
	s := &FilterServer{config: cfg, token: token}
	s.compilePatterns()
	return s
}

func (s *FilterServer) compilePatterns() {
	for _, rule := range s.config.BlockedInputPatterns {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Printf("Warning: invalid input pattern %q: %v", rule.Pattern, err)
			continue
		}
		s.compiledInputs = append(s.compiledInputs, &compiledPattern{rule: rule, pattern: re})
	}
	for _, rule := range s.config.BlockedOutputPatterns {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Printf("Warning: invalid output pattern %q: %v", rule.Pattern, err)
			continue
		}
		s.compiledOutputs = append(s.compiledOutputs, &compiledPattern{rule: rule, pattern: re})
	}
}

// HealthCheck implements ServerInterface.
func (s *FilterServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook implements ServerInterface.
// Filters out blocked toolkits.
func (s *FilterServer) AccessHook(c *gin.Context) {
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

	// Build deny list for blocked toolkits
	deny := make(server.Toolkits)
	for _, blocked := range s.config.BlockedToolkits {
		for toolkitName, toolkitInfo := range req.Toolkits {
			if matchGlob(blocked, toolkitName) {
				deny[toolkitName] = toolkitInfo
				log.Printf("[ACCESS] Blocked toolkit %q for user %q", toolkitName, req.UserId)
			}
		}
	}

	result := &server.AccessHookResult{}
	if len(deny) > 0 {
		result.Deny = &deny
	}
	c.JSON(http.StatusOK, result)
}

// PreHook implements ServerInterface.
// Checks tool inputs against content filtering rules.
func (s *FilterServer) PreHook(c *gin.Context) {
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

	// Rules are checked against each input value on its own, so anchored
	// patterns work.
	fields := leafValues(req.Inputs)

	// Check blocked keywords in inputs
	for _, keyword := range s.config.BlockedKeywords {
		if anyField(fields, func(f string) bool {
			return strings.Contains(strings.ToLower(f), strings.ToLower(keyword))
		}) {
			errMsg := fmt.Sprintf("Input contains blocked content: %q", keyword)
			log.Printf("[PRE] Blocked: %s", errMsg)
			c.JSON(http.StatusOK, server.PreHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &errMsg,
			})
			return
		}
	}

	// Check regex patterns against inputs
	for _, cp := range s.compiledInputs {
		if anyField(fields, cp.pattern.MatchString) {
			msg := cp.rule.Message
			if msg == "" {
				msg = fmt.Sprintf("Input matched blocked pattern: %s", cp.rule.Name)
			}
			log.Printf("[PRE] Blocked by pattern %q: %s", cp.rule.Name, msg)
			c.JSON(http.StatusOK, server.PreHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &msg,
			})
			return
		}
	}

	log.Printf("[PRE] Allowed %s.%s", req.Tool.Toolkit, req.Tool.Name)
	c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
}

// PostHook implements ServerInterface.
// Checks tool outputs against content filtering rules - can block or replace content.
func (s *FilterServer) PostHook(c *gin.Context) {
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

	// Rules are checked against each output value on its own, so anchored
	// patterns work. Content text blocks a remote server sent alongside the
	// output reach the client too, so they are checked and rewritten the same way.
	fields := leafValues(req.Output)
	var content []server.ContentBlock
	if req.Content != nil {
		content = *req.Content
		fields = append(fields, contentValues(content)...)
	}

	// Check blocked keywords in output
	for _, keyword := range s.config.BlockedKeywords {
		if anyField(fields, func(f string) bool {
			return strings.Contains(strings.ToLower(f), strings.ToLower(keyword))
		}) {
			errMsg := fmt.Sprintf("Output contains blocked content: %q", keyword)
			log.Printf("[POST] Blocked: %s", errMsg)
			c.JSON(http.StatusOK, server.PostHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &errMsg,
			})
			return
		}
	}

	// Check regex patterns against output - support block and replace actions
	modified := false
	result := copyValue(req.Output)
	for _, cp := range s.compiledOutputs {
		if anyField(fields, cp.pattern.MatchString) {
			if cp.rule.Action == "block" {
				msg := cp.rule.Message
				if msg == "" {
					msg = fmt.Sprintf("Output matched blocked pattern: %s", cp.rule.Name)
				}
				log.Printf("[POST] Blocked by pattern %q", cp.rule.Name)
				c.JSON(http.StatusOK, server.PostHookResult{
					Code:         server.CHECKFAILED,
					ErrorMessage: &msg,
				})
				return
			}
			if cp.rule.Action == "replace" {
				// Replace matching content in all output string values and content text blocks
				result = replaceInValue(result, cp.pattern, cp.rule.Replacement)
				content = replaceInText(content, cp.pattern, cp.rule.Replacement)
				modified = true
				log.Printf("[POST] Replaced content matching pattern %q", cp.rule.Name)
			}
		}
	}

	if modified {
		override := &server.PostHookOverride{Output: result}
		if req.Content != nil {
			override.Content = &content
		}
		c.JSON(http.StatusOK, server.PostHookResult{
			Code:     server.OK,
			Override: override,
		})
		return
	}

	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

// =============================================================================
// Helper Functions
// =============================================================================

func (s *FilterServer) validateAuth(c *gin.Context) bool {
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

// flattenValue converts any value to a single string for content searching.
func flattenValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case map[string]interface{}:
		var parts []string
		for _, item := range val {
			parts = append(parts, flattenValue(item))
		}
		return strings.Join(parts, " ")
	case []interface{}:
		var parts []string
		for _, item := range val {
			parts = append(parts, flattenValue(item))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// copyValue creates a deep copy of any value.
func copyValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, item := range val {
			result[k] = copyValue(item)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = copyValue(item)
		}
		return result
	default:
		return v
	}
}

// replaceInValue replaces regex matches in all string values recursively.
func replaceInValue(v interface{}, pattern *regexp.Regexp, replacement string) interface{} {
	switch val := v.(type) {
	case string:
		return pattern.ReplaceAllString(val, replacement)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, item := range val {
			result[k] = replaceInValue(item, pattern, replacement)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = replaceInValue(item, pattern, replacement)
		}
		return result
	default:
		return v
	}
}

// leafValues collects every non-null value in v, recursively, as a string.
func leafValues(v interface{}) []string {
	switch val := v.(type) {
	case nil:
		return nil
	case map[string]interface{}:
		var leaves []string
		for _, item := range val {
			leaves = append(leaves, leafValues(item)...)
		}
		return leaves
	case []interface{}:
		var leaves []string
		for _, item := range val {
			leaves = append(leaves, leafValues(item)...)
		}
		return leaves
	default:
		return []string{flattenValue(val)}
	}
}

// contentValues collects the values in content text blocks. Other block types
// pass through unchanged; extend this if your servers put text there.
func contentValues(blocks []server.ContentBlock) []string {
	var leaves []string
	for _, b := range blocks {
		if b.Type == "text" {
			leaves = append(leaves, leafValues(b.AdditionalProperties)...)
		}
	}
	return leaves
}

// anyField reports whether match is true for any of fields.
func anyField(fields []string, match func(string) bool) bool {
	for _, f := range fields {
		if match(f) {
			return true
		}
	}
	return false
}

// replaceInText replaces regex matches in content text blocks and passes other
// blocks through unchanged.
func replaceInText(blocks []server.ContentBlock, pattern *regexp.Regexp, replacement string) []server.ContentBlock {
	result := make([]server.ContentBlock, len(blocks))
	for i, b := range blocks {
		result[i] = b
		if b.Type == "text" {
			result[i].AdditionalProperties = replaceInValue(b.AdditionalProperties, pattern, replacement).(map[string]interface{})
		}
	}
	return result
}

// matchGlob matches a glob pattern against a value.
func matchGlob(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
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

func strPtr(s string) *string { return &s }

func responseCodePtr(c server.ResponseCode) *server.ResponseCode { return &c }

// =============================================================================
// Main
// =============================================================================

func main() {
	var (
		port       int
		token      string
		configFile string
	)

	flag.IntVar(&port, "port", 8888, "Port to listen on")
	flag.StringVar(&token, "token", "", "Bearer token for authentication")
	flag.StringVar(&configFile, "config", "", "Path to YAML config file with filter rules")
	flag.Parse()

	cfg := &Config{
		// Default example: block some keywords
		BlockedKeywords:       []string{},
		BlockedInputPatterns:  []PatternRule{},
		BlockedOutputPatterns: []PatternRule{},
		BlockedToolkits:       []string{},
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config: %v", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
		log.Printf("Loaded filter config from %s", configFile)
	} else {
		log.Println("No config file specified. Use -config to load content filter rules.")
	}

	log.Printf("  Blocked keywords: %d", len(cfg.BlockedKeywords))
	log.Printf("  Blocked input patterns: %d", len(cfg.BlockedInputPatterns))
	log.Printf("  Blocked output patterns: %d", len(cfg.BlockedOutputPatterns))
	log.Printf("  Blocked toolkits: %d", len(cfg.BlockedToolkits))

	srv := NewFilterServer(cfg, token)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	server.RegisterHandlers(router, srv)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\nContent Filter Hook Server listening on %s\n", addr)
	fmt.Printf("  POST /access  - Filter out blocked toolkits\n")
	fmt.Printf("  POST /pre     - Block inputs with prohibited content\n")
	fmt.Printf("  POST /post    - Block or replace prohibited output and content text blocks\n\n")

	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
