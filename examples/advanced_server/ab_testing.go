package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// A/B Testing and Canary Testing
// =============================================================================

// ABTestManager manages experiment state and variant assignment.
type ABTestManager struct {
	mu          sync.RWMutex
	assignments map[string]string          // "user:experiment" -> variant name
	stats       map[string]*ExperimentStats // experiment name -> stats
}

// ExperimentStats tracks usage statistics for an experiment.
type ExperimentStats struct {
	Name            string         `json:"name"`
	TotalRequests   int            `json:"total_requests"`
	VariantCounts   map[string]int `json:"variant_counts"`
	LastRequestTime *time.Time     `json:"last_request_time,omitempty"`
}

// NewABTestManager creates a new A/B test manager.
func NewABTestManager() *ABTestManager {
	return &ABTestManager{
		assignments: make(map[string]string),
		stats:       make(map[string]*ExperimentStats),
	}
}

// SelectVariant picks a variant for a user based on experiment configuration.
// Uses consistent hashing to ensure the same user always gets the same variant.
func (m *ABTestManager) SelectVariant(userID string, exp Experiment) *Variant {
	if len(exp.Variants) == 0 {
		return nil
	}

	// Check if user already has an assignment
	assignmentKey := fmt.Sprintf("%s:%s", userID, exp.Name)
	m.mu.RLock()
	existingVariant, hasAssignment := m.assignments[assignmentKey]
	m.mu.RUnlock()

	if hasAssignment {
		// Return the previously assigned variant
		for i, v := range exp.Variants {
			if v.Name == existingVariant {
				m.recordRequest(exp.Name, v.Name)
				return &exp.Variants[i]
			}
		}
	}

	// Use consistent hashing to select a variant
	variant := selectVariantByHash(userID, exp.Name, exp.Variants)
	if variant == nil {
		return nil
	}

	// Store assignment for consistency
	m.mu.Lock()
	m.assignments[assignmentKey] = variant.Name
	m.mu.Unlock()

	m.recordRequest(exp.Name, variant.Name)
	return variant
}

// FindExperiment looks for an active experiment that matches the given tool.
func (m *ABTestManager) FindExperiment(toolkit, tool string, experiments []Experiment) *Experiment {
	for i, exp := range experiments {
		if !exp.Enabled {
			continue
		}
		if matchesGlob(exp.Toolkit, toolkit) && matchesGlob(exp.Tool, tool) {
			return &experiments[i]
		}
	}
	return nil
}

// GetStats returns stats for all experiments.
func (m *ABTestManager) GetStats() map[string]*ExperimentStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ExperimentStats, len(m.stats))
	for k, v := range m.stats {
		statCopy := *v
		vcCopy := make(map[string]int, len(v.VariantCounts))
		for vk, vv := range v.VariantCounts {
			vcCopy[vk] = vv
		}
		statCopy.VariantCounts = vcCopy
		result[k] = &statCopy
	}
	return result
}

// ResetStats clears all experiment statistics and assignments.
func (m *ABTestManager) ResetStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assignments = make(map[string]string)
	m.stats = make(map[string]*ExperimentStats)
}

func (m *ABTestManager) recordRequest(experimentName, variantName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.stats[experimentName]
	if !ok {
		stats = &ExperimentStats{
			Name:          experimentName,
			VariantCounts: make(map[string]int),
		}
		m.stats[experimentName] = stats
	}

	stats.TotalRequests++
	stats.VariantCounts[variantName]++
	now := time.Now()
	stats.LastRequestTime = &now
}

// selectVariantByHash uses consistent hashing to deterministically
// pick a variant based on user ID and experiment name.
func selectVariantByHash(userID, experimentName string, variants []Variant) *Variant {
	if len(variants) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0
	for _, v := range variants {
		totalWeight += v.Weight
	}
	if totalWeight == 0 {
		return &variants[0]
	}

	// Create a deterministic hash from user + experiment
	hash := sha256.Sum256([]byte(userID + ":" + experimentName))
	// Use first 4 bytes as a uint32
	hashVal := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])

	// Select variant based on weight
	target := int(hashVal % uint32(totalWeight))
	cumulative := 0
	for i, v := range variants {
		cumulative += v.Weight
		if target < cumulative {
			return &variants[i]
		}
	}

	return &variants[len(variants)-1]
}

// =============================================================================
// Tool Registry Client
// =============================================================================

// RegistryTool represents a tool fetched from an external tool registry API.
type RegistryTool struct {
	Name        string   `json:"name"`
	Toolkit     string   `json:"toolkit"`
	Description string   `json:"description"`
	Versions    []string `json:"versions"`
}

// RegistryResponse is the response format from the tool registry API.
type RegistryResponse struct {
	Tools []RegistryTool `json:"tools"`
	Total int            `json:"total"`
}

// FetchToolsFromRegistry queries an external tool registry API for available tools.
// The registry URL and API key come from the config.
func FetchToolsFromRegistry(cfg *ToolRegistryConfig) (*RegistryResponse, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return nil, fmt.Errorf("tool registry not configured: base_url is required")
	}

	url := cfg.BaseURL + "/v1/tools"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tools: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var result RegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode registry response: %w", err)
	}

	return &result, nil
}
