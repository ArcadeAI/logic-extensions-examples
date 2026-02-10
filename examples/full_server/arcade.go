package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// Arcade API Client
// =============================================================================

// ArcadeClient fetches tool definitions from the Arcade API.
type ArcadeClient struct {
	mu         sync.RWMutex
	httpClient *http.Client
	tools      []ArcadeTool
	lastFetch  time.Time
	fetching   bool
	stopChan   chan struct{}
}

// ArcadeTool represents a tool fetched from the Arcade API.
type ArcadeTool struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Toolkit     ArcadeToolkit     `json:"toolkit"`
	Version     string            `json:"version"`
	Inputs      []ArcadeToolInput `json:"inputs"`
	FetchedAt   time.Time         `json:"fetched_at"`
}

// ArcadeToolkit represents a toolkit from the Arcade API.
type ArcadeToolkit struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ArcadeToolInput represents a tool input parameter.
type ArcadeToolInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
}

// ArcadeAPIResponse represents the response from the Arcade tools endpoint.
type ArcadeAPIResponse struct {
	Items      []ArcadeToolRaw `json:"items"`
	TotalCount int             `json:"total_count"`
	Offset     int             `json:"offset"`
	Limit      int             `json:"limit"`
}

// ArcadeToolRaw represents the raw tool data from the API.
type ArcadeToolRaw struct {
	FullyQualifiedName string                 `json:"fully_qualified_name"`
	Description        string                 `json:"description"`
	Toolkit            map[string]interface{} `json:"toolkit"`
	Version            string                 `json:"version"`
	Input              map[string]interface{} `json:"input"`
}

// NewArcadeClient creates a new Arcade API client.
func NewArcadeClient() *ArcadeClient {
	return &ArcadeClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		tools:      []ArcadeTool{},
		stopChan:   make(chan struct{}),
	}
}

// FetchTools fetches tools from the Arcade API.
func (c *ArcadeClient) FetchTools(ctx context.Context, cfg *ArcadeConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.APIURL == "" {
		return fmt.Errorf("arcade integration not configured")
	}

	c.mu.Lock()
	if c.fetching {
		c.mu.Unlock()
		return fmt.Errorf("fetch already in progress")
	}
	c.fetching = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.fetching = false
		c.mu.Unlock()
	}()

	url := fmt.Sprintf("%s/v1/tools", cfg.APIURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch tools: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var apiResp ArcadeAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		// Try parsing as a direct array
		var rawTools []ArcadeToolRaw
		if err2 := json.Unmarshal(body, &rawTools); err2 != nil {
			return fmt.Errorf("failed to parse API response: %w", err)
		}
		apiResp.Items = rawTools
	}

	tools := make([]ArcadeTool, 0, len(apiResp.Items))
	now := time.Now()
	for _, raw := range apiResp.Items {
		tool := ArcadeTool{
			Name:        raw.FullyQualifiedName,
			Description: raw.Description,
			Version:     raw.Version,
			FetchedAt:   now,
		}

		// Extract toolkit info
		if raw.Toolkit != nil {
			if name, ok := raw.Toolkit["name"].(string); ok {
				tool.Toolkit.Name = name
			}
			if desc, ok := raw.Toolkit["description"].(string); ok {
				tool.Toolkit.Description = desc
			}
		}

		// Extract input parameters
		if raw.Input != nil {
			if params, ok := raw.Input["parameters"].([]interface{}); ok {
				for _, p := range params {
					if param, ok := p.(map[string]interface{}); ok {
						input := ArcadeToolInput{}
						if name, ok := param["name"].(string); ok {
							input.Name = name
						}
						if desc, ok := param["description"].(string); ok {
							input.Description = desc
						}
						if t, ok := param["type"].(string); ok {
							input.Type = t
						}
						if req, ok := param["required"].(bool); ok {
							input.Required = req
						}
						tool.Inputs = append(tool.Inputs, input)
					}
				}
			}
		}

		tools = append(tools, tool)
	}

	c.mu.Lock()
	c.tools = tools
	c.lastFetch = now
	c.mu.Unlock()

	log.Printf("Fetched %d tools from Arcade API", len(tools))
	return nil
}

// GetTools returns the cached tools.
func (c *ArcadeClient) GetTools() []ArcadeTool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]ArcadeTool{}, c.tools...)
}

// GetLastFetch returns when tools were last fetched.
func (c *ArcadeClient) GetLastFetch() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetch
}

// StartPeriodicFetch starts a background goroutine to fetch tools periodically.
func (c *ArcadeClient) StartPeriodicFetch(cfgMgr *ConfigManager) {
	go func() {
		for {
			cfg := cfgMgr.Get()
			if cfg.Arcade != nil && cfg.Arcade.Enabled {
				interval := time.Duration(cfg.Arcade.FetchIntervalSeconds) * time.Second
				if interval < 30*time.Second {
					interval = 30 * time.Second
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := c.FetchTools(ctx, cfg.Arcade); err != nil {
					log.Printf("Periodic tool fetch failed: %v", err)
				}
				cancel()

				select {
				case <-time.After(interval):
					continue
				case <-c.stopChan:
					return
				}
			} else {
				// Not enabled, check again in 30s
				select {
				case <-time.After(30 * time.Second):
					continue
				case <-c.stopChan:
					return
				}
			}
		}
	}()
}

// Stop stops the periodic fetch goroutine.
func (c *ArcadeClient) Stop() {
	close(c.stopChan)
}
