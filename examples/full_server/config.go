package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// Root Configuration
// =============================================================================

// Config is the root configuration loaded from YAML.
type Config struct {
	Health    *HealthConfig    `yaml:"health" json:"health"`
	Access    *AccessConfig    `yaml:"access" json:"access"`
	Pre       *PreConfig       `yaml:"pre" json:"pre"`
	Post      *PostConfig      `yaml:"post" json:"post"`
	PII       *PIIConfig       `yaml:"pii" json:"pii"`
	ABTesting *ABTestingConfig `yaml:"ab_testing" json:"ab_testing"`
	Arcade    *ArcadeConfig    `yaml:"arcade" json:"arcade"`
}

// =============================================================================
// Health Configuration
// =============================================================================

// HealthConfig controls health endpoint behavior.
type HealthConfig struct {
	Status string `yaml:"status" json:"status"` // healthy, degraded, unhealthy
}

// =============================================================================
// Access Control Configuration
// =============================================================================

// AccessConfig controls access hook behavior.
type AccessConfig struct {
	DefaultAction string       `yaml:"default_action" json:"default_action"`
	Rules         []AccessRule `yaml:"rules" json:"rules"`
}

// AccessRule defines a single access control rule.
type AccessRule struct {
	UserID       string `yaml:"user_id" json:"user_id"`
	ToolkitMatch string `yaml:"toolkit" json:"toolkit"`
	ToolMatch    string `yaml:"tool" json:"tool"`
	Action       string `yaml:"action" json:"action"`
	Reason       string `yaml:"reason" json:"reason"`
}

// =============================================================================
// Pre-Execution Configuration
// =============================================================================

// PreConfig controls pre-execution hook behavior.
type PreConfig struct {
	DefaultAction string    `yaml:"default_action" json:"default_action"`
	Rules         []PreRule `yaml:"rules" json:"rules"`
}

// PreRule defines a single pre-execution rule.
type PreRule struct {
	UserID       string             `yaml:"user_id" json:"user_id"`
	Toolkit      string             `yaml:"toolkit" json:"toolkit"`
	Tool         string             `yaml:"tool" json:"tool"`
	ExecutionID  string             `yaml:"execution_id" json:"execution_id"`
	InputMatch   string             `yaml:"input_match" json:"input_match"`
	Action       string             `yaml:"action" json:"action"`
	ErrorMessage string             `yaml:"error_message" json:"error_message"`
	Override     *PreOverrideConfig `yaml:"override" json:"override"`
}

// PreOverrideConfig defines what to override in pre-hook.
type PreOverrideConfig struct {
	Inputs  map[string]interface{} `yaml:"inputs" json:"inputs"`
	Secrets map[string]string      `yaml:"secrets" json:"secrets"`
	Headers map[string]string      `yaml:"headers" json:"headers"`
	Server  *ServerOverride        `yaml:"server" json:"server"`
}

// ServerOverride defines server routing override.
type ServerOverride struct {
	Name string `yaml:"name" json:"name"`
	URI  string `yaml:"uri" json:"uri"`
	Type string `yaml:"type" json:"type"`
}

// =============================================================================
// Post-Execution Configuration
// =============================================================================

// PostConfig controls post-execution hook behavior.
type PostConfig struct {
	DefaultAction string     `yaml:"default_action" json:"default_action"`
	Rules         []PostRule `yaml:"rules" json:"rules"`
}

// PostRule defines a single post-execution rule.
type PostRule struct {
	UserID       string              `yaml:"user_id" json:"user_id"`
	Toolkit      string              `yaml:"toolkit" json:"toolkit"`
	Tool         string              `yaml:"tool" json:"tool"`
	ExecutionID  string              `yaml:"execution_id" json:"execution_id"`
	Success      *bool               `yaml:"success" json:"success"`
	OutputMatch  string              `yaml:"output_match" json:"output_match"`
	Action       string              `yaml:"action" json:"action"`
	ErrorMessage string              `yaml:"error_message" json:"error_message"`
	Override     *PostOverrideConfig `yaml:"override" json:"override"`
}

// PostOverrideConfig defines what to override in post-hook.
type PostOverrideConfig struct {
	Output map[string]interface{} `yaml:"output" json:"output"`
}

// =============================================================================
// PII Redaction Configuration
// =============================================================================

// PIIConfig controls PII detection and redaction.
type PIIConfig struct {
	Enabled        bool              `yaml:"enabled" json:"enabled"`
	Mode           string            `yaml:"mode" json:"mode"` // "redact" or "block"
	Types          PIITypes          `yaml:"types" json:"types"`
	CustomPatterns []CustomPIIPattern `yaml:"custom_patterns" json:"custom_patterns"`
}

// PIITypes defines which PII types to detect.
type PIITypes struct {
	Email       bool `yaml:"email" json:"email"`
	IPAddress   bool `yaml:"ip_address" json:"ip_address"`
	SSN         bool `yaml:"ssn" json:"ssn"`
	PhoneNumber bool `yaml:"phone_number" json:"phone_number"`
	CreditCard  bool `yaml:"credit_card" json:"credit_card"`
	DateOfBirth bool `yaml:"date_of_birth" json:"date_of_birth"`
}

// CustomPIIPattern defines a custom regex pattern for PII detection.
type CustomPIIPattern struct {
	Name        string `yaml:"name" json:"name"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Replacement string `yaml:"replacement" json:"replacement"`
}

// =============================================================================
// A/B Testing Configuration
// =============================================================================

// ABTestingConfig controls A/B and canary testing.
type ABTestingConfig struct {
	Enabled     bool         `yaml:"enabled" json:"enabled"`
	Experiments []Experiment `yaml:"experiments" json:"experiments"`
}

// Experiment defines an A/B or canary test.
type Experiment struct {
	Name           string          `yaml:"name" json:"name"`
	Toolkit        string          `yaml:"toolkit" json:"toolkit"`
	Tool           string          `yaml:"tool" json:"tool"`
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Variants       []Variant       `yaml:"variants" json:"variants"`
	UserTargeting  *UserTargeting  `yaml:"user_targeting" json:"user_targeting"`
}

// Variant defines a variant in an A/B test.
type Variant struct {
	Name   string          `yaml:"name" json:"name"`
	Weight int             `yaml:"weight" json:"weight"` // percentage 0-100
	Server *ServerOverride `yaml:"server" json:"server"`
}

// UserTargeting defines optional user targeting for experiments.
type UserTargeting struct {
	Include []string `yaml:"include" json:"include"`
	Exclude []string `yaml:"exclude" json:"exclude"`
}

// =============================================================================
// Arcade API Configuration
// =============================================================================

// ArcadeConfig controls Arcade API integration.
type ArcadeConfig struct {
	Enabled              bool   `yaml:"enabled" json:"enabled"`
	APIURL               string `yaml:"api_url" json:"api_url"`
	APIKey               string `yaml:"api_key" json:"api_key"`
	FetchIntervalSeconds int    `yaml:"fetch_interval_seconds" json:"fetch_interval_seconds"`
}

// =============================================================================
// Configuration Manager
// =============================================================================

// ConfigManager handles loading, saving, and watching configuration.
type ConfigManager struct {
	mu       sync.RWMutex
	config   *Config
	filePath string
}

// NewConfigManager creates a new ConfigManager with defaults.
func NewConfigManager(filePath string) *ConfigManager {
	return &ConfigManager{
		filePath: filePath,
		config:   DefaultConfig(),
	}
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Health: &HealthConfig{Status: "healthy"},
		Access: &AccessConfig{DefaultAction: "allow", Rules: []AccessRule{}},
		Pre:    &PreConfig{DefaultAction: "proceed", Rules: []PreRule{}},
		Post:   &PostConfig{DefaultAction: "proceed", Rules: []PostRule{}},
		PII: &PIIConfig{
			Enabled: false,
			Mode:    "redact",
			Types: PIITypes{
				Email:       true,
				IPAddress:   true,
				SSN:         true,
				PhoneNumber: true,
				CreditCard:  true,
				DateOfBirth: true,
			},
			CustomPatterns: []CustomPIIPattern{},
		},
		ABTesting: &ABTestingConfig{
			Enabled:     false,
			Experiments: []Experiment{},
		},
		Arcade: &ArcadeConfig{
			Enabled:              false,
			APIURL:               "https://api.arcade.dev",
			APIKey:               "",
			FetchIntervalSeconds: 300,
		},
	}
}

// Get returns the current configuration (read-only copy).
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// Set replaces the full configuration.
func (cm *ConfigManager) Set(cfg *Config) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config = cfg
}

// Update merges non-nil fields from the provided config.
func (cm *ConfigManager) Update(cfg *Config) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cfg.Health != nil {
		cm.config.Health = cfg.Health
	}
	if cfg.Access != nil {
		cm.config.Access = cfg.Access
	}
	if cfg.Pre != nil {
		cm.config.Pre = cfg.Pre
	}
	if cfg.Post != nil {
		cm.config.Post = cfg.Post
	}
	if cfg.PII != nil {
		cm.config.PII = cfg.PII
	}
	if cfg.ABTesting != nil {
		cm.config.ABTesting = cfg.ABTesting
	}
	if cfg.Arcade != nil {
		cm.config.Arcade = cfg.Arcade
	}
}

// LoadFromFile loads configuration from the YAML file.
func (cm *ConfigManager) LoadFromFile() error {
	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	cm.Update(&cfg)
	return nil
}

// SaveToFile writes the current configuration to the YAML file.
func (cm *ConfigManager) SaveToFile() error {
	cm.mu.RLock()
	data, err := yaml.Marshal(cm.config)
	cm.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// FilePath returns the configuration file path.
func (cm *ConfigManager) FilePath() string {
	return cm.filePath
}

// WatchFile starts watching the config file for changes and reloads automatically.
func (cm *ConfigManager) WatchFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(cm.filePath); err != nil {
		log.Printf("Failed to watch config file: %v", err)
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Println("Config file changed, reloading...")
				if err := cm.LoadFromFile(); err != nil {
					log.Printf("Failed to reload config: %v", err)
				} else {
					log.Println("Configuration reloaded successfully")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		case <-sigChan:
			return
		}
	}
}
