// ab_testing is a minimal CATE webhook server that demonstrates how to
// perform A/B testing and canary deployments by routing tool executions
// to different server variants.
//
// It uses the pre-execution hook to intercept tool requests and override
// the server routing based on experiment configuration and user assignment.
//
// Usage:
//
//	go run ./examples/ab_testing -port 8890
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// A/B Testing Configuration
// =============================================================================

// Variant represents one arm of an experiment.
type Variant struct {
	Name       string // e.g., "control", "treatment"
	Weight     int    // Percentage of traffic (0-100)
	ServerName string // Server name for routing
	ServerURI  string // Server URI for routing
	ServerType string // "arcade" or "mcp"
}

// Experiment defines an A/B or canary test.
type Experiment struct {
	Name     string
	Toolkit  string // Pattern to match toolkit
	Tool     string // Pattern to match tool
	Variants []Variant
}

// Assignment records which variant a user was assigned to.
type Assignment struct {
	ExperimentName string    `json:"experiment"`
	VariantName    string    `json:"variant"`
	UserID         string    `json:"user_id"`
	AssignedAt     time.Time `json:"assigned_at"`
}

// =============================================================================
// A/B Testing Server
// =============================================================================

// ABTestServer implements the CATE webhook ServerInterface.
type ABTestServer struct {
	experiments []Experiment
	mu          sync.RWMutex
	assignments map[string]*Assignment // key: "experiment:user_id"
}

// NewABTestServer creates a server with example experiments.
func NewABTestServer() *ABTestServer {
	return &ABTestServer{
		assignments: make(map[string]*Assignment),
		experiments: []Experiment{
			{
				// A/B test: 80/20 split between two versions of a search tool
				Name:    "search-v2-rollout",
				Toolkit: "Search",
				Tool:    "WebSearch",
				Variants: []Variant{
					{
						Name:       "control",
						Weight:     80,
						ServerName: "search-v1",
						ServerURI:  "http://search-v1:8080",
						ServerType: "arcade",
					},
					{
						Name:       "treatment",
						Weight:     20,
						ServerName: "search-v2",
						ServerURI:  "http://search-v2:8080",
						ServerType: "arcade",
					},
				},
			},
			{
				// Canary: 95/5 split for a new email tool version
				Name:    "email-canary",
				Toolkit: "Email",
				Tool:    "*",
				Variants: []Variant{
					{
						Name:       "stable",
						Weight:     95,
						ServerName: "email-stable",
						ServerURI:  "http://email-stable:8080",
						ServerType: "arcade",
					},
					{
						Name:       "canary",
						Weight:     5,
						ServerName: "email-canary",
						ServerURI:  "http://email-canary:8080",
						ServerType: "arcade",
					},
				},
			},
		},
	}
}

// HealthCheck implements webhook.ServerInterface.
func (s *ABTestServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook passes through - A/B testing doesn't affect tool visibility.
func (s *ABTestServer) AccessHook(c *gin.Context) {
	c.JSON(http.StatusOK, server.AccessHookResult{})
}

// PreHook is where A/B testing routing happens.
// It intercepts tool execution requests and overrides the server routing
// to direct the request to the assigned variant's server.
func (s *ABTestServer) PreHook(c *gin.Context) {
	var req server.PreHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, server.ErrorResponse{
			Error: strPtr("invalid request: " + err.Error()),
		})
		return
	}

	userID := ""
	if req.Context.UserId != nil {
		userID = *req.Context.UserId
	}

	// Find a matching experiment for this tool
	experiment := s.findExperiment(req.Tool.Toolkit, req.Tool.Name)
	if experiment == nil {
		// No experiment for this tool, pass through
		c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
		return
	}

	// Assign a variant to the user (sticky - same user always gets same variant)
	variant := s.assignVariant(experiment, userID)
	if variant == nil {
		c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
		return
	}

	log.Printf("[A/B] %s.%s -> experiment=%q user=%q variant=%q server=%s",
		req.Tool.Toolkit, req.Tool.Name, experiment.Name, userID, variant.Name, variant.ServerURI)

	// Override the server routing to point to the variant's server
	c.JSON(http.StatusOK, server.PreHookResult{
		Code: server.OK,
		Override: &server.PreHookOverride{
			Server: &server.ServerInfo{
				Name: variant.ServerName,
				Uri:  variant.ServerURI,
				Type: server.ServerInfoType(variant.ServerType),
			},
		},
	})
}

// PostHook passes through - A/B testing routing only happens in pre-hook.
func (s *ABTestServer) PostHook(c *gin.Context) {
	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

// findExperiment finds an experiment matching the given toolkit and tool.
func (s *ABTestServer) findExperiment(toolkit, tool string) *Experiment {
	for i := range s.experiments {
		exp := &s.experiments[i]
		if matchPattern(exp.Toolkit, toolkit) && matchPattern(exp.Tool, tool) {
			return exp
		}
	}
	return nil
}

// assignVariant uses a deterministic hash to assign a user to a variant.
// This ensures the same user always gets the same variant (sticky assignment),
// which is critical for consistent A/B test results.
func (s *ABTestServer) assignVariant(exp *Experiment, userID string) *Variant {
	cacheKey := fmt.Sprintf("%s:%s", exp.Name, userID)

	// Check if already assigned
	s.mu.RLock()
	if a, ok := s.assignments[cacheKey]; ok {
		for i := range exp.Variants {
			if exp.Variants[i].Name == a.VariantName {
				s.mu.RUnlock()
				return &exp.Variants[i]
			}
		}
	}
	s.mu.RUnlock()

	// Compute a deterministic bucket from the user ID and experiment name.
	// This is the key mechanism: hashing ensures consistent assignment
	// without needing to store state externally.
	hash := sha256.Sum256([]byte(cacheKey))
	bucket := int(binary.BigEndian.Uint32(hash[:4])) % 100

	// Walk the variants and find which bucket range the user falls into
	cumulative := 0
	var selected *Variant
	for i := range exp.Variants {
		cumulative += exp.Variants[i].Weight
		if bucket < cumulative {
			selected = &exp.Variants[i]
			break
		}
	}

	// Fallback to last variant
	if selected == nil && len(exp.Variants) > 0 {
		selected = &exp.Variants[len(exp.Variants)-1]
	}

	// Cache the assignment
	if selected != nil {
		s.mu.Lock()
		s.assignments[cacheKey] = &Assignment{
			ExperimentName: exp.Name,
			VariantName:    selected.Name,
			UserID:         userID,
			AssignedAt:     time.Now(),
		}
		s.mu.Unlock()
	}

	return selected
}

// =============================================================================
// Helpers
// =============================================================================

func matchPattern(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
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

func strPtr(s string) *string {
	return &s
}

// =============================================================================
// Main
// =============================================================================

func main() {
	port := flag.Int("port", 8890, "Port to listen on")
	flag.Parse()

	srv := NewABTestServer()

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	server.RegisterHandlers(router, srv)

	// Admin endpoint to view assignments
	router.GET("/_assignments", func(c *gin.Context) {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		assignments := make([]*Assignment, 0, len(srv.assignments))
		for _, a := range srv.assignments {
			assignments = append(assignments, a)
		}
		c.JSON(http.StatusOK, gin.H{
			"count":       len(assignments),
			"assignments": assignments,
		})
	})

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("  A/B Testing Example")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  Port: %d\n", *port)
	fmt.Println()
	fmt.Println("  This example demonstrates:")
	fmt.Println("  - A/B testing via server routing override (pre-hook)")
	fmt.Println("  - Deterministic variant assignment (hash-based)")
	fmt.Println("  - Sticky assignment (same user = same variant)")
	fmt.Println()
	fmt.Println("  Experiments:")
	for _, exp := range srv.experiments {
		fmt.Printf("    %s (%s.%s):\n", exp.Name, exp.Toolkit, exp.Tool)
		for _, v := range exp.Variants {
			fmt.Printf("      %s: %d%% -> %s\n", v.Name, v.Weight, v.ServerURI)
		}
	}
	fmt.Println()
	fmt.Println("  Admin: GET /_assignments - view variant assignments")
	fmt.Println(strings.Repeat("=", 50))

	addr := fmt.Sprintf(":%d", *port)
	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
