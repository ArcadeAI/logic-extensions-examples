package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ArcadeAI/logical-extensions-examples/pkg/server"
)

// =============================================================================
// PII Detection and Redaction
// =============================================================================

// PIIDetector detects and redacts personally identifiable information from text.
type PIIDetector struct {
	patterns map[string]*regexp.Regexp
	labels   map[string]string // pattern name -> redacted label
}

// NewPIIDetector creates a PIIDetector with patterns based on the provided PIIConfig.
func NewPIIDetector(cfg *PIIConfig) *PIIDetector {
	d := &PIIDetector{
		patterns: make(map[string]*regexp.Regexp),
		labels:   make(map[string]string),
	}

	if cfg == nil {
		return d
	}

	if cfg.Types.Email {
		d.patterns["email"] = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
		d.labels["email"] = "[EMAIL REDACTED]"
	}
	if cfg.Types.IPv4 {
		d.patterns["ipv4"] = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
		d.labels["ipv4"] = "[IP REDACTED]"
	}
	if cfg.Types.SSN {
		d.patterns["ssn"] = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
		d.labels["ssn"] = "[SSN REDACTED]"
	}
	if cfg.Types.Phone {
		d.patterns["phone"] = regexp.MustCompile(`(?:\+?\b1[-.\s]?\(?|\(|\b)\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
		d.labels["phone"] = "[PHONE REDACTED]"
	}
	if cfg.Types.CreditCard {
		d.patterns["credit_card"] = regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
		d.labels["credit_card"] = "[CREDIT CARD REDACTED]"
	}
	if cfg.Types.DateOfBirth {
		d.patterns["date_of_birth"] = regexp.MustCompile(`\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b`)
		d.labels["date_of_birth"] = "[DOB REDACTED]"
	}

	// Add custom patterns
	for _, custom := range cfg.Custom {
		re, err := regexp.Compile(custom.Pattern)
		if err != nil {
			continue
		}
		replacement := custom.Replacement
		if replacement == "" {
			replacement = fmt.Sprintf("[%s REDACTED]", strings.ToUpper(custom.Name))
		}
		d.patterns[custom.Name] = re
		d.labels[custom.Name] = replacement
	}

	return d
}

// DetectPII checks if a string contains any PII and returns the types found.
func (d *PIIDetector) DetectPII(text string) []PIIMatch {
	var matches []PIIMatch

	for name, pattern := range d.patterns {
		locs := pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, PIIMatch{
				Type:  name,
				Value: text[loc[0]:loc[1]],
				Start: loc[0],
				End:   loc[1],
			})
		}
	}

	return matches
}

// ContainsPII returns true if the text contains any PII.
func (d *PIIDetector) ContainsPII(text string) bool {
	for _, pattern := range d.patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// RedactString replaces all PII in a string with redaction labels.
func (d *PIIDetector) RedactString(text string) string {
	result := text
	for name, pattern := range d.patterns {
		result = pattern.ReplaceAllString(result, d.labels[name])
	}
	return result
}

// RedactMap recursively redacts PII from all string values in a map.
func (d *PIIDetector) RedactMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	result := make(map[string]interface{}, len(data))
	for key, val := range data {
		result[key] = d.redactValue(val)
	}
	return result
}

// ScanMap checks all string values in a map for PII and returns all matches found.
func (d *PIIDetector) ScanMap(data map[string]interface{}) []PIIMatch {
	var allMatches []PIIMatch
	d.scanValue(data, "", &allMatches)
	return allMatches
}

func (d *PIIDetector) redactValue(val interface{}) interface{} {
	switch v := val.(type) {
	case string:
		return d.RedactString(v)
	case map[string]interface{}:
		return d.RedactMap(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = d.redactValue(item)
		}
		return result
	default:
		return val
	}
}

func (d *PIIDetector) scanValue(val interface{}, path string, matches *[]PIIMatch) {
	switch v := val.(type) {
	case string:
		found := d.DetectPII(v)
		for i := range found {
			found[i].Path = path
		}
		*matches = append(*matches, found...)
	case map[string]interface{}:
		for key, item := range v {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}
			d.scanValue(item, newPath, matches)
		}
	case []interface{}:
		for i, item := range v {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			d.scanValue(item, newPath, matches)
		}
	}
}

// PIIMatch represents a single PII detection match.
type PIIMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Path  string `json:"path,omitempty"` // JSON path where PII was found
}

// PIIScanResult is the result of scanning content for PII.
type PIIScanResult struct {
	ContainsPII bool           `json:"contains_pii"`
	Matches     []PIIMatch     `json:"matches"`
	TypeCounts  map[string]int `json:"type_counts"`
}

// ScanAndSummarize scans a map for PII and returns a summary.
func (d *PIIDetector) ScanAndSummarize(data map[string]interface{}) PIIScanResult {
	return d.ScanAndSummarizeAny(data)
}

// ScanAndSummarizeAny scans any value (string, map, slice, etc.) for PII and returns a summary.
func (d *PIIDetector) ScanAndSummarizeAny(data interface{}) PIIScanResult {
	var matches []PIIMatch
	d.scanValue(data, "", &matches)
	return summarize(matches)
}

// ScanAndSummarizeContent scans the string fields of post-hook content blocks
// (text, uri, annotations, _meta, and an embedded resource's text) for PII and
// returns a summary.
func (d *PIIDetector) ScanAndSummarizeContent(blocks []server.ContentBlock) PIIScanResult {
	var matches []PIIMatch
	for i, b := range blocks {
		d.scanBlockFields(b.AdditionalProperties, fmt.Sprintf("content[%d]", i), &matches)
	}
	return summarize(matches)
}

func summarize(matches []PIIMatch) PIIScanResult {
	counts := make(map[string]int)
	for _, m := range matches {
		counts[m.Type]++
	}
	return PIIScanResult{
		ContainsPII: len(matches) > 0,
		Matches:     matches,
		TypeCounts:  counts,
	}
}

// RedactAny recursively redacts PII from any value (string, map, slice, etc.).
func (d *PIIDetector) RedactAny(data interface{}) interface{} {
	return d.redactValue(data)
}

// RedactContent redacts PII from the string fields of post-hook content blocks,
// keeping each block's type and base64 payloads unchanged.
func (d *PIIDetector) RedactContent(blocks []server.ContentBlock) []server.ContentBlock {
	result := make([]server.ContentBlock, len(blocks))
	for i, b := range blocks {
		result[i] = server.ContentBlock{Type: b.Type, AdditionalProperties: d.redactBlockFields(b.AdditionalProperties)}
	}
	return result
}

// isBinaryField reports whether a content block field holds a base64 payload
// (image and audio "data", a resource's "blob"). Regexes could corrupt these,
// so they are left as-is.
func isBinaryField(key string) bool {
	return key == "data" || key == "blob"
}

func (d *PIIDetector) scanBlockFields(fields map[string]interface{}, path string, matches *[]PIIMatch) {
	for key, val := range fields {
		if isBinaryField(key) {
			continue
		}
		newPath := path + "." + key
		if resource, ok := val.(map[string]interface{}); ok && key == "resource" {
			d.scanBlockFields(resource, newPath, matches)
			continue
		}
		d.scanValue(val, newPath, matches)
	}
}

func (d *PIIDetector) redactBlockFields(fields map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(fields))
	for key, val := range fields {
		resource, isMap := val.(map[string]interface{})
		switch {
		case isBinaryField(key):
			result[key] = val
		case isMap && key == "resource":
			result[key] = d.redactBlockFields(resource)
		default:
			result[key] = d.redactValue(val)
		}
	}
	return result
}
