// ab_testing demonstrates how to do A/B and canary testing with tool calls.
//
// This minimal hook server shows:
//   - Routing tool calls to different servers/versions based on experiment config
//   - Consistent user assignment via deterministic hashing
//   - Fetching available tools from an external tool registry API
//   - Tracking experiment statistics
//
// Usage:
//
//	go run ./examples/contextual_access/ab_testing -port 8888 -config ./examples/contextual_access/ab_testing/example-config.yaml
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// Configuration
// =============================================================================

// Config defines A/B testing experiments.
type Config struct {
	// RegistryURL is the base URL of an external tool registry API
	RegistryURL string `yaml:"registry_url" json:"registry_url"`
	// RegistryKey is the API key for the tool registry
	RegistryKey string `yaml:"registry_key" json:"registry_key"`
	// Experiments is the list of active experiments
	Experiments []Experiment `yaml:"experiments" json:"experiments"`
}

// Experiment defines a single A/B or canary test.
type Experiment struct {
	Name     string    `yaml:"name" json:"name"`
	Enabled  bool      `yaml:"enabled" json:"enabled"`
	Toolkit  string    `yaml:"toolkit" json:"toolkit"` // glob pattern
	Tool     string    `yaml:"tool" json:"tool"`       // glob pattern
	Mode     string    `yaml:"mode" json:"mode"`       // "ab" or "canary"
	Variants []Variant `yaml:"variants" json:"variants"`
}

// Variant defines one arm of an experiment.
type Variant struct {
	Name    string `yaml:"name" json:"name"`
	Weight  int    `yaml:"weight" json:"weight"` // relative weight (0-100)
	Version string `yaml:"version" json:"version"`
}

// =============================================================================
// Server
// =============================================================================

// ABServer implements the webhook ServerInterface.
type ABServer struct {
	mu          sync.RWMutex
	config      *Config
	token       string
	assignments map[string]string           // "user:experiment" -> variant name
	stats       map[string]*ExperimentStats // experiment name -> stats
}

// ExperimentStats tracks request counts per variant.
type ExperimentStats struct {
	TotalRequests int            `json:"total_requests"`
	VariantCounts map[string]int `json:"variant_counts"`
}

func NewABServer(cfg *Config, token string) *ABServer {
	return &ABServer{
		config:      cfg,
		token:       token,
		assignments: make(map[string]string),
		stats:       make(map[string]*ExperimentStats),
	}
}

// HealthCheck implements ServerInterface.
func (s *ABServer) HealthCheck(c *gin.Context) {
	status := server.Healthy
	c.JSON(http.StatusOK, server.HealthResponse{Status: &status})
}

// AccessHook implements ServerInterface. Pass-through.
func (s *ABServer) AccessHook(c *gin.Context) {
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
	// A/B testing doesn't affect tool visibility
	c.JSON(http.StatusOK, server.AccessHookResult{})
}

// PreHook implements ServerInterface.
// This is where A/B routing happens - route tool calls to different servers/versions.
func (s *ABServer) PreHook(c *gin.Context) {
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

	// Find matching experiment
	exp := s.findExperiment(req.Tool.Toolkit, req.Tool.Name)
	if exp == nil {
		// No experiment matches - pass through
		c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
		return
	}

	// Select variant for this user
	variant := s.selectVariant(userID, exp)
	if variant == nil {
		c.JSON(http.StatusOK, server.PreHookResult{Code: server.OK})
		return
	}

	log.Printf("[A/B] %s: user=%q assigned to variant=%q (experiment=%q, mode=%s)",
		req.Tool.Name, userID, variant.Name, exp.Name, exp.Mode)

	result := &server.PreHookResult{Code: server.OK}

	// A/B variant selected - pass through with OK
	// (server routing overrides were removed from the schema;
	//  version filtering is handled at the access hook level)

	c.JSON(http.StatusOK, result)
}

// PostHook implements ServerInterface. Pass-through.
func (s *ABServer) PostHook(c *gin.Context) {
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
	// Pass-through - could be extended to log results per variant
	c.JSON(http.StatusOK, server.PostHookResult{Code: server.OK})
}

// =============================================================================
// Experiment Logic
// =============================================================================

// findExperiment returns the first enabled experiment matching the tool.
func (s *ABServer) findExperiment(toolkit, tool string) *Experiment {
	for i, exp := range s.config.Experiments {
		if !exp.Enabled {
			continue
		}
		if matchGlob(exp.Toolkit, toolkit) && matchGlob(exp.Tool, tool) {
			return &s.config.Experiments[i]
		}
	}
	return nil
}

// selectVariant picks a variant using consistent hashing for user stickiness.
func (s *ABServer) selectVariant(userID string, exp *Experiment) *Variant {
	if len(exp.Variants) == 0 {
		return nil
	}

	// Check for existing assignment
	key := userID + ":" + exp.Name
	s.mu.RLock()
	existingName, hasAssignment := s.assignments[key]
	s.mu.RUnlock()

	if hasAssignment {
		for i, v := range exp.Variants {
			if v.Name == existingName {
				s.recordStat(exp.Name, v.Name)
				return &exp.Variants[i]
			}
		}
	}

	// Consistent hash selection
	totalWeight := 0
	for _, v := range exp.Variants {
		totalWeight += v.Weight
	}
	if totalWeight == 0 {
		return &exp.Variants[0]
	}

	hash := sha256.Sum256([]byte(userID + ":" + exp.Name))
	hashVal := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
	target := int(hashVal % uint32(totalWeight))

	cumulative := 0
	for i, v := range exp.Variants {
		cumulative += v.Weight
		if target < cumulative {
			// Store assignment
			s.mu.Lock()
			s.assignments[key] = v.Name
			s.mu.Unlock()
			s.recordStat(exp.Name, v.Name)
			return &exp.Variants[i]
		}
	}

	return &exp.Variants[len(exp.Variants)-1]
}

func (s *ABServer) recordStat(expName, variantName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.stats[expName]
	if !ok {
		stats = &ExperimentStats{VariantCounts: make(map[string]int)}
		s.stats[expName] = stats
	}
	stats.TotalRequests++
	stats.VariantCounts[variantName]++
}

// =============================================================================
// Admin Endpoints
// =============================================================================

func (s *ABServer) handleGetStats(c *gin.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c.JSON(http.StatusOK, s.stats)
}

func (s *ABServer) handleFetchTools(c *gin.Context) {
	if s.config.RegistryURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "registry_url not configured"})
		return
	}

	url := s.config.RegistryURL + "/v1/tools"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if s.config.RegistryKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.RegistryKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tools interface{}
	if err := json.Unmarshal(body, &tools); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to parse registry response"})
		return
	}
	c.JSON(http.StatusOK, tools)
}

// =============================================================================
// Helpers
// =============================================================================

func (s *ABServer) validateAuth(c *gin.Context) bool {
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
	flag.StringVar(&configFile, "config", "", "Path to YAML config with experiments")
	flag.Parse()

	cfg := &Config{}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config: %v", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
		log.Printf("Loaded %d experiments from %s", len(cfg.Experiments), configFile)
	} else {
		log.Println("No config file specified. Use -config to load experiments.")
	}

	for _, exp := range cfg.Experiments {
		status := "disabled"
		if exp.Enabled {
			status = "enabled"
		}
		log.Printf("  Experiment %q (%s): %s.%s mode=%s variants=%d",
			exp.Name, status, exp.Toolkit, exp.Tool, exp.Mode, len(exp.Variants))
	}

	srv := NewABServer(cfg, token)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Webhook endpoints
	server.RegisterHandlers(router, srv)

	// Admin endpoints
	router.GET("/stats", srv.handleGetStats)
	router.POST("/registry/fetch", srv.handleFetchTools)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\nA/B Testing Hook Server listening on %s\n", addr)
	fmt.Printf("  POST /pre     - Route tool calls to experiment variants\n")
	fmt.Printf("  GET  /stats   - View experiment statistics\n")
	fmt.Printf("  POST /registry/fetch - Fetch tools from registry\n\n")

	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
