// content_filter is a minimal CATE webhook server that demonstrates how to
// block users, filter tools, and reject requests based on content matching.
//
// It shows the three hook points in action:
//   - Access hook: Block specific users or toolkits from being discovered
//   - Pre-execution hook: Block requests based on input content
//   - Post-execution hook: Block responses based on output content
//
// Usage:
//
//	go run ./examples/content_filter -port 8888
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
// Configuration
// =============================================================================

// BlockedUser is a user that should be denied all access.
type BlockedUser struct {
	UserID string
	Reason string
}

// BlockedToolkit is a toolkit that should be hidden from all users.
type BlockedToolkit struct {
	Pattern string // Exact, glob, or ~regex
	Reason  string
}

// ContentRule blocks requests/responses containing specific content.
type ContentRule struct {
	Toolkit      string // Pattern to match toolkit
	Tool         string // Pattern to match tool
	FieldMatch   string // "field contains value" or "field=value"
	ErrorMessage string
}

// FilterConfig holds all filtering rules.
type FilterConfig struct {
	BlockedUsers    []BlockedUser
	BlockedToolkits []BlockedToolkit
	InputRules      []ContentRule // Applied in pre-hook
	OutputRules     []ContentRule // Applied in post-hook
}

// =============================================================================
// Filter Server
// =============================================================================

// FilterServer implements the CATE webhook ServerInterface.
type FilterServer struct {
	config FilterConfig
}

// NewFilterServer creates a server with example filtering rules.
func NewFilterServer() *FilterServer {
	return &FilterServer{
		config: FilterConfig{
			// Block specific users
			BlockedUsers: []BlockedUser{
				{UserID: "suspended-user", Reason: "Account suspended"},
				{UserID: "terminated-user", Reason: "Account terminated"},
			},

			// Block specific toolkits
			BlockedToolkits: []BlockedToolkit{
				{Pattern: "DangerousToolkit", Reason: "Toolkit is disabled"},
				{Pattern: "Internal*", Reason: "Internal tools not available"},
			},

			// Block requests with certain input content
			InputRules: []ContentRule{
				{
					Toolkit:      "Email",
					Tool:         "sendEmail",
					FieldMatch:   "to contains @blocked.com",
					ErrorMessage: "Cannot send emails to blocked domains",
				},
				{
					Toolkit:      "*",
					Tool:         "*",
					FieldMatch:   "password",
					ErrorMessage: "Cannot pass password fields directly",
				},
			},

			// Block responses with certain output content
			OutputRules: []ContentRule{
				{
					Toolkit:      "Database",
					Tool:         "*",
					FieldMatch:   "data contains CONFIDENTIAL",
					ErrorMessage: "Response contains confidential data",
				},
			},
		},
	}
}

// HealthCheck implements webhook.ServerInterface.
func (s *FilterServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook demonstrates blocking users and toolkits at the access level.
// This controls what tools a user can even see - blocked tools never appear
// in the tool list.
func (s *FilterServer) AccessHook(c *gin.Context) {
	var req server.AccessHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request: " + err.Error()),
		})
		return
	}

	// Check if user is blocked
	for _, blocked := range s.config.BlockedUsers {
		if req.UserId == blocked.UserID {
			log.Printf("[ACCESS] Blocked user %q: %s", req.UserId, blocked.Reason)
			// Return empty "only" list to deny everything
			empty := make(server.Toolkits)
			c.JSON(http.StatusOK, server.AccessHookResult{
				Only: &empty,
			})
			return
		}
	}

	// Filter out blocked toolkits
	deny := make(server.Toolkits)
	for toolkitName, toolkitInfo := range req.Toolkits {
		for _, blocked := range s.config.BlockedToolkits {
			if matchPattern(blocked.Pattern, toolkitName) {
				log.Printf("[ACCESS] Blocked toolkit %q for user %q: %s",
					toolkitName, req.UserId, blocked.Reason)
				deny[toolkitName] = toolkitInfo
			}
		}
	}

	result := &server.AccessHookResult{}
	if len(deny) > 0 {
		result.Deny = &deny
	}

	c.JSON(http.StatusOK, result)
}

// PreHook demonstrates blocking requests based on input content.
// This runs before tool execution and can stop a request from proceeding.
func (s *FilterServer) PreHook(c *gin.Context) {
	var req server.PreHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request: " + err.Error()),
		})
		return
	}

	// Check each content rule against the inputs
	for _, rule := range s.config.InputRules {
		if !matchPattern(rule.Toolkit, req.Tool.Toolkit) {
			continue
		}
		if !matchPattern(rule.Tool, req.Tool.Name) {
			continue
		}
		if matchContent(rule.FieldMatch, req.Inputs) {
			log.Printf("[PRE] Blocked %s.%s: %s", req.Tool.Toolkit, req.Tool.Name, rule.ErrorMessage)
			c.JSON(http.StatusOK, server.PreHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &rule.ErrorMessage,
			})
			return
		}
	}

	// Allow the request to proceed
	c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
}

// PostHook demonstrates blocking responses based on output content.
// This runs after tool execution and can prevent the response from reaching
// the agent if it contains blocked content.
func (s *FilterServer) PostHook(c *gin.Context) {
	var req server.PostHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request: " + err.Error()),
		})
		return
	}

	// Check each content rule against the output
	for _, rule := range s.config.OutputRules {
		if !matchPattern(rule.Toolkit, req.Tool.Toolkit) {
			continue
		}
		if !matchPattern(rule.Tool, req.Tool.Name) {
			continue
		}
		if matchContent(rule.FieldMatch, req.Output) {
			log.Printf("[POST] Blocked output from %s.%s: %s",
				req.Tool.Toolkit, req.Tool.Name, rule.ErrorMessage)
			c.JSON(http.StatusOK, server.PostHookResult{
				Code:         server.CHECKFAILED,
				ErrorMessage: &rule.ErrorMessage,
			})
			return
		}
	}

	// Allow the response to pass through
	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

// =============================================================================
// Helpers
// =============================================================================

// matchPattern matches a value against a pattern (exact, glob, or regex).
func matchPattern(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
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
		regexStr := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return pattern == value
}

// matchContent checks if a map contains content matching an expression.
// Supports: "key contains value", "key=value", or just "key" (exists check).
func matchContent(expr string, data map[string]interface{}) bool {
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		key, sub := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if val, ok := data[key]; ok {
			return strings.Contains(fmt.Sprintf("%v", val), sub)
		}
		return false
	}
	if strings.Contains(expr, "=") {
		parts := strings.SplitN(expr, "=", 2)
		key, expected := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if val, ok := data[key]; ok {
			return fmt.Sprintf("%v", val) == expected
		}
		return false
	}
	// Just check if the key exists
	_, ok := data[expr]
	return ok
}

func strPtr(s string) *string {
	return &s
}

// =============================================================================
// Main
// =============================================================================

func main() {
	port := flag.Int("port", 8888, "Port to listen on")
	flag.Parse()

	srv := NewFilterServer()

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	server.RegisterHandlers(router, srv)

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("  Content Filter Example")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  Port: %d\n", *port)
	fmt.Println()
	fmt.Println("  This example demonstrates:")
	fmt.Println("  - Blocking users at the access hook")
	fmt.Println("  - Filtering toolkits at the access hook")
	fmt.Println("  - Blocking requests by input content (pre)")
	fmt.Println("  - Blocking responses by output content (post)")
	fmt.Println()
	fmt.Println("  Blocked users: suspended-user, terminated-user")
	fmt.Println("  Blocked toolkits: DangerousToolkit, Internal*")
	fmt.Println("  Input rules: emails to @blocked.com, password fields")
	fmt.Println("  Output rules: responses containing CONFIDENTIAL")
	fmt.Println(strings.Repeat("=", 50))

	addr := fmt.Sprintf(":%d", *port)
	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
