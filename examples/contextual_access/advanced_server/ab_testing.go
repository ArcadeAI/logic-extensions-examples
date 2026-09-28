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
	assignments map[string]string           // "user:experiment" -> variant name
	stats       map[string]*ExperimentStats // experiment name -> stats
}

// ExperimentStats tracks usage statistics for an experiment.
type ExperimentStats struct {
	Name            string                     `json:"name"`
	TotalRequests   int                        `json:"total_requests"`
	VariantCounts   map[string]int             `json:"variant_counts"`
	UniqueUsers     map[string]map[string]bool `json:"-"`             // variant -> set of user IDs (not serialised)
	VariantUsers    map[string]int             `json:"variant_users"` // variant -> unique user count
	LastRequestTime *time.Time                 `json:"last_request_time,omitempty"`
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
				m.recordRequest(exp.Name, v.Name, userID)
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

	m.recordRequest(exp.Name, variant.Name, userID)
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

		// Compute unique-user counts per variant
		vuCopy := make(map[string]int, len(v.UniqueUsers))
		for vk, users := range v.UniqueUsers {
			vuCopy[vk] = len(users)
		}
		statCopy.VariantUsers = vuCopy

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

func (m *ABTestManager) recordRequest(experimentName, variantName, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.stats[experimentName]
	if !ok {
		stats = &ExperimentStats{
			Name:          experimentName,
			VariantCounts: make(map[string]int),
			UniqueUsers:   make(map[string]map[string]bool),
		}
		m.stats[experimentName] = stats
	}

	stats.TotalRequests++
	stats.VariantCounts[variantName]++

	// Track unique users per variant
	if stats.UniqueUsers == nil {
		stats.UniqueUsers = make(map[string]map[string]bool)
	}
	if stats.UniqueUsers[variantName] == nil {
		stats.UniqueUsers[variantName] = make(map[string]bool)
	}
	stats.UniqueUsers[variantName][userID] = true

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

// RegistryTool represents a tool in the dashboard-friendly format.
type RegistryTool struct {
	Name        string   `json:"name"`
	Toolkit     string   `json:"toolkit"`
	Description string   `json:"description"`
	Versions    []string `json:"versions"`
}

// RegistryResponse is the response format returned to the dashboard.
type RegistryResponse struct {
	Tools []RegistryTool `json:"tools"`
	Total int            `json:"total"`
}

// arcadeToolResponse represents a single tool from the Arcade engine API.
type arcadeToolResponse struct {
	Name               string                `json:"name"`
	Description        string                `json:"description"`
	FullyQualifiedName string                `json:"fully_qualified_name"`
	QualifiedName      string                `json:"qualified_name"`
	Toolkit            arcadeToolkitResponse `json:"toolkit"`
}

// arcadeToolkitResponse represents toolkit info nested in a tool response.
type arcadeToolkitResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// arcadeToolsPage is the paginated response from the Arcade engine's /v1/tools endpoint.
type arcadeToolsPage struct {
	Items      []arcadeToolResponse `json:"items"`
	TotalCount int                  `json:"total_count"`
	Limit      int                  `json:"limit"`
	Offset     int                  `json:"offset"`
	PageCount  int                  `json:"page_count"`
}

// FetchToolsFromRegistry queries the Arcade engine API for available tools.
// It handles pagination and transforms the engine response into a simpler format
// for the dashboard to display.
func FetchToolsFromRegistry(cfg *ToolRegistryConfig) (*RegistryResponse, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return nil, fmt.Errorf("tool registry not configured: base_url is required")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	var allTools []arcadeToolResponse
	offset := 0
	limit := 100

	for {
		page, err := fetchToolsPage(client, cfg, limit, offset)
		if err != nil {
			return nil, err
		}

		allTools = append(allTools, page.Items...)

		// Stop when we've fetched everything or the page was empty.
		if len(allTools) >= page.TotalCount || len(page.Items) == 0 {
			break
		}
		offset += len(page.Items)
	}

	// Transform Arcade engine tools into RegistryTool format, grouping versions.
	type toolKey struct {
		toolkit  string
		toolName string
	}
	toolMap := make(map[toolKey]*RegistryTool)
	var toolOrder []toolKey // preserve insertion order

	for _, t := range allTools {
		key := toolKey{toolkit: t.Toolkit.Name, toolName: t.Name}
		if rt, ok := toolMap[key]; ok {
			// Add version if not already present.
			if t.Toolkit.Version != "" {
				found := false
				for _, v := range rt.Versions {
					if v == t.Toolkit.Version {
						found = true
						break
					}
				}
				if !found {
					rt.Versions = append(rt.Versions, t.Toolkit.Version)
				}
			}
		} else {
			rt := &RegistryTool{
				Name:        t.Name,
				Toolkit:     t.Toolkit.Name,
				Description: t.Description,
			}
			if t.Toolkit.Version != "" {
				rt.Versions = []string{t.Toolkit.Version}
			}
			toolMap[key] = rt
			toolOrder = append(toolOrder, key)
		}
	}

	tools := make([]RegistryTool, 0, len(toolOrder))
	for _, key := range toolOrder {
		tools = append(tools, *toolMap[key])
	}

	return &RegistryResponse{
		Tools: tools,
		Total: len(tools),
	}, nil
}

// fetchToolsPage fetches a single page of tools from the Arcade engine API.
func fetchToolsPage(client *http.Client, cfg *ToolRegistryConfig, limit, offset int) (*arcadeToolsPage, error) {
	url := fmt.Sprintf("%s/v1/tools?limit=%d&offset=%d&include_all_versions=true", cfg.BaseURL, limit, offset)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tools: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var page arcadeToolsPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &page, nil
}
