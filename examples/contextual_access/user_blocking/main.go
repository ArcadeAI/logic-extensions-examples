// user_blocking demonstrates how to block specific users from accessing tools.
//
// This minimal hook server shows:
//   - Blocking users in the access hook (they won't see the tools)
//   - Blocking users in the pre-execution hook (they can't run the tools)
//   - Using a simple YAML config with a list of blocked users
//
// Usage:
//
//	go run ./examples/contextual_access/user_blocking -port 8888 -config ./examples/contextual_access/user_blocking/example-config.yaml
//	go run ./examples/contextual_access/user_blocking -port 8888 -block "user1,user2,user3"
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// Config defines the list of blocked users.
type Config struct {
	BlockedUsers []BlockedUser `yaml:"blocked_users" json:"blocked_users"`
}

// BlockedUser defines a user that should be blocked.
type BlockedUser struct {
	UserID string `yaml:"user_id" json:"user_id"`
	Reason string `yaml:"reason" json:"reason"`
}

// BlockingServer implements the webhook ServerInterface.
type BlockingServer struct {
	config *Config
	token  string
}

func NewBlockingServer(cfg *Config, token string) *BlockingServer {
	return &BlockingServer{config: cfg, token: token}
}

// HealthCheck implements ServerInterface.
func (s *BlockingServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook implements ServerInterface.
// Blocked users will not see any tools.
func (s *BlockingServer) AccessHook(c *gin.Context) {
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

	// Check if user is blocked
	if reason := s.isBlocked(req.UserId); reason != "" {
		log.Printf("[ACCESS] Blocked user %q: %s", req.UserId, reason)

		// Deny ALL tools for blocked users
		deny := make(server.Toolkits)
		for toolkitName, toolkitInfo := range req.Toolkits {
			deny[toolkitName] = toolkitInfo
		}
		c.JSON(http.StatusOK, server.AccessHookResult{Deny: &deny})
		return
	}

	// Allow all tools for non-blocked users
	log.Printf("[ACCESS] Allowed user %q", req.UserId)
	c.JSON(http.StatusOK, server.AccessHookResult{})
}

// PreHook implements ServerInterface.
// Provides a second layer of defense - blocks execution even if access check is bypassed.
func (s *BlockingServer) PreHook(c *gin.Context) {
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

	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// Check if user is blocked
	if reason := s.isBlocked(userID); reason != "" {
		log.Printf("[PRE] Blocked execution for user %q on %s.%s: %s", userID, req.Tool.Toolkit, req.Tool.Name, reason)
		errMsg := fmt.Sprintf("User is not authorized: %s", reason)
		c.JSON(http.StatusOK, server.PreHookResult{
			Code:         server.CHECKFAILED,
			ErrorMessage: &errMsg,
		})
		return
	}

	log.Printf("[PRE] Allowed execution for user %q on %s.%s", userID, req.Tool.Toolkit, req.Tool.Name)
	c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
}

// PostHook implements ServerInterface.
// Pass-through - no post-processing needed for user blocking.
func (s *BlockingServer) PostHook(c *gin.Context) {
	if !s.validateAuth(c) {
		return
	}

	// Read the request body but don't need to process it
	var req server.PostHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request body: " + err.Error()),
			Code:  responseCodePtr(server.CHECKFAILED),
		})
		return
	}

	// Pass through - allow all post-execution responses
	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

// isBlocked checks if a user is in the blocked list.
// Returns the reason if blocked, or empty string if allowed.
func (s *BlockingServer) isBlocked(userID string) string {
	for _, blocked := range s.config.BlockedUsers {
		if blocked.UserID == userID {
			return blocked.Reason
		}
	}
	return ""
}

func (s *BlockingServer) validateAuth(c *gin.Context) bool {
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

func strPtr(s string) *string { return &s }

func responseCodePtr(c server.ResponseCode) *server.ResponseCode { return &c }

func main() {
	var (
		port       int
		token      string
		configFile string
		blockList  string
	)

	flag.IntVar(&port, "port", 8888, "Port to listen on")
	flag.StringVar(&token, "token", "", "Bearer token for authentication")
	flag.StringVar(&configFile, "config", "", "Path to YAML config file with blocked users")
	flag.StringVar(&blockList, "block", "", "Comma-separated list of user IDs to block")
	flag.Parse()

	cfg := &Config{}

	// Load from config file
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config: %v", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
		log.Printf("Loaded %d blocked users from %s", len(cfg.BlockedUsers), configFile)
	}

	// Add users from command line
	if blockList != "" {
		for _, uid := range strings.Split(blockList, ",") {
			uid = strings.TrimSpace(uid)
			if uid != "" {
				cfg.BlockedUsers = append(cfg.BlockedUsers, BlockedUser{
					UserID: uid,
					Reason: "blocked via command line",
				})
			}
		}
	}

	if len(cfg.BlockedUsers) == 0 {
		log.Println("Warning: no blocked users configured. Use -config or -block to specify users.")
	} else {
		log.Printf("Blocking %d users:", len(cfg.BlockedUsers))
		for _, u := range cfg.BlockedUsers {
			log.Printf("  - %s (%s)", u.UserID, u.Reason)
		}
	}

	srv := NewBlockingServer(cfg, token)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	server.RegisterHandlers(router, srv)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\nUser Blocking Hook Server listening on %s\n", addr)
	fmt.Printf("  POST /access  - Block users from seeing tools\n")
	fmt.Printf("  POST /pre     - Block users from executing tools\n\n")

	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
