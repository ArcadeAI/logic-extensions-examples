package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// =============================================================================
// PII Detector / Redactor
// =============================================================================

// PIIPattern represents a named PII detection pattern.
type PIIPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// PIIDetector detects and redacts PII from text and structured data.
type PIIDetector struct {
	// patterns is an ordered slice - order matters because longer patterns
	// (like credit cards) must be matched before shorter ones (like phone numbers)
	// to avoid partial matches.
	patterns []PIIPattern
}

// NewPIIDetector creates a new PIIDetector with compiled regex patterns.
// Patterns are ordered so that longer/more-specific patterns (credit_card)
// are applied before shorter/more-general ones (phone_number).
func NewPIIDetector() *PIIDetector {
	return &PIIDetector{
		patterns: []PIIPattern{
			{Name: "email", Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
			{Name: "ip_address", Pattern: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
			{Name: "credit_card", Pattern: regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)},
			{Name: "ssn", Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
			{Name: "phone_number", Pattern: regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)},
			{Name: "date_of_birth", Pattern: regexp.MustCompile(`\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b`)},
		},
	}
}

// PIIMatch represents a detected PII instance.
type PIIMatch struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	StartIndex int    `json:"start_index"`
	EndIndex   int    `json:"end_index"`
}

// replacementForType returns the replacement string for a PII type.
func replacementForType(piiType string) string {
	switch piiType {
	case "email":
		return "[EMAIL_REDACTED]"
	case "ip_address":
		return "[IP_REDACTED]"
	case "ssn":
		return "[SSN_REDACTED]"
	case "phone_number":
		return "[PHONE_REDACTED]"
	case "credit_card":
		return "[CC_REDACTED]"
	case "date_of_birth":
		return "[DOB_REDACTED]"
	default:
		return "[REDACTED]"
	}
}

// DetectPII scans text for PII and returns all matches.
func (d *PIIDetector) DetectPII(text string, cfg *PIIConfig) []PIIMatch {
	var matches []PIIMatch

	enabledTypes := d.getEnabledTypes(cfg)

	for _, p := range d.patterns {
		if !enabledTypes[p.Name] {
			continue
		}
		locs := p.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, PIIMatch{
				Type:       p.Name,
				Value:      text[loc[0]:loc[1]],
				StartIndex: loc[0],
				EndIndex:   loc[1],
			})
		}
	}

	// Check custom patterns
	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			continue
		}
		locs := re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, PIIMatch{
				Type:       cp.Name,
				Value:      text[loc[0]:loc[1]],
				StartIndex: loc[0],
				EndIndex:   loc[1],
			})
		}
	}

	return matches
}

// RedactText replaces PII in text with redaction markers.
func (d *PIIDetector) RedactText(text string, cfg *PIIConfig) (string, []PIIMatch) {
	var allMatches []PIIMatch
	result := text

	enabledTypes := d.getEnabledTypes(cfg)

	for _, p := range d.patterns {
		if !enabledTypes[p.Name] {
			continue
		}
		found := p.Pattern.FindAllString(result, -1)
		for _, f := range found {
			allMatches = append(allMatches, PIIMatch{Type: p.Name, Value: f})
		}
		replacement := replacementForType(p.Name)
		result = p.Pattern.ReplaceAllString(result, replacement)
	}

	// Apply custom patterns
	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			continue
		}
		found := re.FindAllString(result, -1)
		for _, f := range found {
			allMatches = append(allMatches, PIIMatch{Type: cp.Name, Value: f})
		}
		replacement := cp.Replacement
		if replacement == "" {
			replacement = fmt.Sprintf("[%s_REDACTED]", strings.ToUpper(cp.Name))
		}
		result = re.ReplaceAllString(result, replacement)
	}

	return result, allMatches
}

// ContainsPII checks if text contains any PII.
func (d *PIIDetector) ContainsPII(text string, cfg *PIIConfig) bool {
	enabledTypes := d.getEnabledTypes(cfg)

	for _, p := range d.patterns {
		if !enabledTypes[p.Name] {
			continue
		}
		if p.Pattern.MatchString(text) {
			return true
		}
	}

	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}

	return false
}

// RedactMap recursively redacts PII from a map of string to interface{}.
func (d *PIIDetector) RedactMap(data map[string]interface{}, cfg *PIIConfig) (map[string]interface{}, []PIIMatch) {
	var allMatches []PIIMatch
	result := make(map[string]interface{}, len(data))

	for k, v := range data {
		redacted, matches := d.redactValue(v, cfg)
		result[k] = redacted
		allMatches = append(allMatches, matches...)
	}

	return result, allMatches
}

// redactValue recursively redacts PII from any value.
func (d *PIIDetector) redactValue(v interface{}, cfg *PIIConfig) (interface{}, []PIIMatch) {
	switch val := v.(type) {
	case string:
		redacted, matches := d.RedactText(val, cfg)
		return redacted, matches
	case map[string]interface{}:
		redacted, matches := d.RedactMap(val, cfg)
		return redacted, matches
	case []interface{}:
		var allMatches []PIIMatch
		result := make([]interface{}, len(val))
		for i, item := range val {
			redacted, matches := d.redactValue(item, cfg)
			result[i] = redacted
			allMatches = append(allMatches, matches...)
		}
		return result, allMatches
	case json.Number:
		return val, nil
	default:
		// For numbers, booleans, nil - return as-is
		return v, nil
	}
}

// CheckMapForPII checks if any value in a map contains PII.
func (d *PIIDetector) CheckMapForPII(data map[string]interface{}, cfg *PIIConfig) bool {
	for _, v := range data {
		if d.checkValueForPII(v, cfg) {
			return true
		}
	}
	return false
}

// checkValueForPII recursively checks if a value contains PII.
func (d *PIIDetector) checkValueForPII(v interface{}, cfg *PIIConfig) bool {
	switch val := v.(type) {
	case string:
		return d.ContainsPII(val, cfg)
	case map[string]interface{}:
		return d.CheckMapForPII(val, cfg)
	case []interface{}:
		for _, item := range val {
			if d.checkValueForPII(item, cfg) {
				return true
			}
		}
	}
	return false
}

// getEnabledTypes returns a map of enabled PII type names.
func (d *PIIDetector) getEnabledTypes(cfg *PIIConfig) map[string]bool {
	return map[string]bool{
		"email":         cfg.Types.Email,
		"ip_address":    cfg.Types.IPAddress,
		"ssn":           cfg.Types.SSN,
		"phone_number":  cfg.Types.PhoneNumber,
		"credit_card":   cfg.Types.CreditCard,
		"date_of_birth": cfg.Types.DateOfBirth,
	}
}
