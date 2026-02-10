package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// A/B Testing Engine
// =============================================================================

// ABTestingEngine manages experiments and variant assignment.
type ABTestingEngine struct {
	mu          sync.RWMutex
	assignments map[string]*VariantAssignment // key: "experiment:user_id"
}

// VariantAssignment records a user's variant assignment for an experiment.
type VariantAssignment struct {
	ExperimentName string    `json:"experiment_name"`
	VariantName    string    `json:"variant_name"`
	UserID         string    `json:"user_id"`
	AssignedAt     time.Time `json:"assigned_at"`
}

// NewABTestingEngine creates a new A/B testing engine.
func NewABTestingEngine() *ABTestingEngine {
	return &ABTestingEngine{
		assignments: make(map[string]*VariantAssignment),
	}
}

// AssignVariant determines which variant a user should receive for an experiment.
// It uses a deterministic hash of the user ID and experiment name to ensure
// the same user always gets the same variant (sticky assignment).
func (e *ABTestingEngine) AssignVariant(experiment *Experiment, userID string) *Variant {
	if !experiment.Enabled || len(experiment.Variants) == 0 {
		return nil
	}

	// Check user targeting
	if experiment.UserTargeting != nil {
		if !e.matchesTargeting(experiment.UserTargeting, userID) {
			return nil
		}
	}

	// Check cache
	cacheKey := fmt.Sprintf("%s:%s", experiment.Name, userID)
	e.mu.RLock()
	if assignment, ok := e.assignments[cacheKey]; ok {
		for i := range experiment.Variants {
			if experiment.Variants[i].Name == assignment.VariantName {
				e.mu.RUnlock()
				return &experiment.Variants[i]
			}
		}
	}
	e.mu.RUnlock()

	// Compute deterministic hash for consistent assignment
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", experiment.Name, userID)))
	bucket := int(binary.BigEndian.Uint32(hash[:4])) % 100

	// Find the variant based on weight distribution
	cumulative := 0
	var selected *Variant
	for i := range experiment.Variants {
		cumulative += experiment.Variants[i].Weight
		if bucket < cumulative {
			selected = &experiment.Variants[i]
			break
		}
	}

	// Fallback to last variant if weights don't sum to 100
	if selected == nil && len(experiment.Variants) > 0 {
		selected = &experiment.Variants[len(experiment.Variants)-1]
	}

	// Cache the assignment
	if selected != nil {
		e.mu.Lock()
		e.assignments[cacheKey] = &VariantAssignment{
			ExperimentName: experiment.Name,
			VariantName:    selected.Name,
			UserID:         userID,
			AssignedAt:     time.Now(),
		}
		e.mu.Unlock()
	}

	return selected
}

// FindExperiment finds an active experiment matching the given toolkit and tool.
func (e *ABTestingEngine) FindExperiment(cfg *ABTestingConfig, toolkit, tool string) *Experiment {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	for i := range cfg.Experiments {
		exp := &cfg.Experiments[i]
		if !exp.Enabled {
			continue
		}
		if matchesGlob(exp.Toolkit, toolkit) && matchesGlob(exp.Tool, tool) {
			return exp
		}
	}
	return nil
}

// GetAssignments returns all current variant assignments.
func (e *ABTestingEngine) GetAssignments() []*VariantAssignment {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*VariantAssignment, 0, len(e.assignments))
	for _, a := range e.assignments {
		result = append(result, a)
	}
	return result
}

// ClearAssignments clears all cached variant assignments.
func (e *ABTestingEngine) ClearAssignments() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.assignments = make(map[string]*VariantAssignment)
}

// matchesTargeting checks if a user ID matches the targeting rules.
func (e *ABTestingEngine) matchesTargeting(targeting *UserTargeting, userID string) bool {
	// Check excludes first
	for _, pattern := range targeting.Exclude {
		if matchesGlob(pattern, userID) {
			return false
		}
	}

	// If includes are specified, user must match at least one
	if len(targeting.Include) > 0 {
		for _, pattern := range targeting.Include {
			if matchesGlob(pattern, userID) {
				return true
			}
		}
		return false
	}

	// No include list means everyone is included
	return true
}

// matchesGlob matches a pattern against a value. Supports exact, glob (*), and regex (~prefix).
func matchesGlob(pattern, value string) bool {
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
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return pattern == value
}
