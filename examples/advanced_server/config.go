package main

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// =============================================================================
// Configuration Types
// =============================================================================

// Config is the root configuration loaded from YAML.
type Config struct {
	Health    *HealthConfig    `yaml:"health" json:"health"`
	Access    *AccessConfig    `yaml:"access" json:"access"`
	Pre       *PreConfig       `yaml:"pre" json:"pre"`
	Post      *PostConfig      `yaml:"post" json:"post"`
	PII       *PIIConfig       `yaml:"pii" json:"pii"`
	ABTesting *ABTestingConfig `yaml:"ab_testing" json:"ab_testing"`
}

// HealthConfig controls health endpoint behavior.
type HealthConfig struct {
	Status string `yaml:"status" json:"status"` // healthy, degraded, unhealthy
}

// AccessConfig controls access hook behavior.
type AccessConfig struct {
	DefaultAction string       `yaml:"default_action" json:"default_action"`
	Rules         []AccessRule `yaml:"rules" json:"rules"`
}

// AccessRule defines a single access control rule.
type AccessRule struct {
	UserID  string `yaml:"user_id" json:"user_id"`
	Toolkit string `yaml:"toolkit" json:"toolkit"`
	Tool    string `yaml:"tool" json:"tool"`
	Action  string `yaml:"action" json:"action"`
	Reason  string `yaml:"reason" json:"reason"`
}

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
}

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

// PIIConfig controls PII redaction behavior.
type PIIConfig struct {
	Enabled bool               `yaml:"enabled" json:"enabled"`
	Action  string             `yaml:"action" json:"action"` // "redact" or "block"
	Types   PIITypes           `yaml:"types" json:"types"`
	Custom  []PIICustomPattern `yaml:"custom" json:"custom"`
}

// PIITypes controls which PII types to detect.
type PIITypes struct {
	Email       bool `yaml:"email" json:"email"`
	IPv4        bool `yaml:"ipv4" json:"ipv4"`
	SSN         bool `yaml:"ssn" json:"ssn"`
	Phone       bool `yaml:"phone" json:"phone"`
	CreditCard  bool `yaml:"credit_card" json:"credit_card"`
	DateOfBirth bool `yaml:"date_of_birth" json:"date_of_birth"`
}

// PIICustomPattern defines a custom PII detection pattern.
type PIICustomPattern struct {
	Name        string `yaml:"name" json:"name"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Replacement string `yaml:"replacement" json:"replacement"`
}

// ABTestingConfig controls A/B and canary testing.
type ABTestingConfig struct {
	Enabled      bool                `yaml:"enabled" json:"enabled"`
	ToolRegistry *ToolRegistryConfig `yaml:"tool_registry" json:"tool_registry"`
	Experiments  []Experiment        `yaml:"experiments" json:"experiments"`
}

// ToolRegistryConfig configures the external tool registry API.
type ToolRegistryConfig struct {
	BaseURL string `yaml:"base_url" json:"base_url"`
	APIKey  string `yaml:"api_key" json:"api_key"`
}

// Experiment defines an A/B or canary test.
type Experiment struct {
	Name     string    `yaml:"name" json:"name"`
	Enabled  bool      `yaml:"enabled" json:"enabled"`
	Toolkit  string    `yaml:"toolkit" json:"toolkit"`
	Tool     string    `yaml:"tool" json:"tool"`
	Mode     string    `yaml:"mode" json:"mode"` // "ab" or "canary"
	Variants []Variant `yaml:"variants" json:"variants"`
}

// Variant defines a single variant in an experiment.
type Variant struct {
	Name    string `yaml:"name" json:"name"`
	Weight  int    `yaml:"weight" json:"weight"` // 0-100, relative weight
	Version string `yaml:"version" json:"version"`
}

// =============================================================================
// Configuration Manager
// =============================================================================

// ConfigManager handles loading, saving, and thread-safe access to configuration.
type ConfigManager struct {
	mu         sync.RWMutex
	config     *Config
	configPath string
}

// NewConfigManager creates a new ConfigManager with default configuration.
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
		config:     DefaultConfig(),
	}
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Health: &HealthConfig{Status: "healthy"},
		Access: &AccessConfig{
			DefaultAction: "allow",
			Rules:         []AccessRule{},
		},
		Pre: &PreConfig{
			DefaultAction: "proceed",
			Rules:         []PreRule{},
		},
		Post: &PostConfig{
			DefaultAction: "proceed",
			Rules:         []PostRule{},
		},
		PII: &PIIConfig{
			Enabled: false,
			Action:  "redact",
			Types: PIITypes{
				Email:       true,
				IPv4:        true,
				SSN:         true,
				Phone:       true,
				CreditCard:  true,
				DateOfBirth: false,
			},
			Custom: []PIICustomPattern{},
		},
		ABTesting: &ABTestingConfig{
			Enabled: false,
			ToolRegistry: &ToolRegistryConfig{
				BaseURL: "",
				APIKey:  "",
			},
			Experiments: []Experiment{},
		},
	}
}

// Load reads configuration from the YAML file at configPath.
func (cm *ConfigManager) Load() error {
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Merge with defaults - only override non-nil fields
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

	return nil
}

// Save writes the current configuration to the YAML file at configPath.
func (cm *ConfigManager) Save() error {
	cm.mu.RLock()
	data, err := yaml.Marshal(cm.config)
	cm.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Get returns the current configuration (read-only snapshot).
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// Update replaces the current configuration with the provided one, merging non-nil fields.
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
}

// ConfigPath returns the path to the configuration file.
func (cm *ConfigManager) ConfigPath() string {
	return cm.configPath
}
