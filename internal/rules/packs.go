// Rule packs are the application layer of Dolly Sensor. Protocol knowledge
// (FTP, SSH, HTTP, ...) does not live in Go code: it ships as .dly files that
// contain validated rule definitions. Operators import a pack and its rules
// become ordinary catalog entries they can edit, disable, or delete. The core
// sensor stays protocol-agnostic.
package rules

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

//go:embed templates/*.dly

var templateFS embed.FS

// Pack is one importable rule pack. A .dly file is this structure encoded as
// JSON. Rule entries carry no IDs or timestamps; those are assigned at import
// time so the same pack can be imported into independent sensors.
type Pack struct {
	Name        string `json:"name"`
	Version     int    `json:"version"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
}

// PackSummary is the catalog view of a pack.
type PackSummary struct {
	Name        string   `json:"name"`
	Version     int      `json:"version"`
	Description string   `json:"description"`
	RuleCount   int      `json:"rule_count"`
	RuleNames   []string `json:"rule_names"`
}

// ImportResult reports what an import did: the rules that were created and
// the pack rule names that already existed (same pack, same name) and were
// skipped so double-importing is safe.
type ImportResult struct {
	Imported []Rule   `json:"imported"`
	Skipped  []string `json:"skipped,omitempty"`
}

var (
	ErrInvalidPack = errors.New("invalid rule pack")
)

// NormalizePack validates the pack envelope: a name, a positive version, and
// at least one rule with unique names. Individual rules are validated by the
// rule engine at import time, because they depend on the protected network.
func NormalizePack(pack *Pack) error {
	if pack == nil {
		return fmt.Errorf("%w: empty pack", ErrInvalidPack)
	}
	pack.Name = strings.TrimSpace(pack.Name)
	pack.Description = strings.TrimSpace(pack.Description)
	if pack.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidPack)
	}
	if len(pack.Name) > maxPackNameLength {
		return fmt.Errorf("%w: name must be %d characters or fewer", ErrInvalidPack, maxPackNameLength)
	}
	if pack.Version < 1 {
		return fmt.Errorf("%w: version must be a positive integer", ErrInvalidPack)
	}
	if len(pack.Description) > 2000 {
		return fmt.Errorf("%w: description must be 2000 characters or fewer", ErrInvalidPack)
	}
	if len(pack.Rules) == 0 {
		return fmt.Errorf("%w: pack contains no rules", ErrInvalidPack)
	}
	seen := map[string]bool{}
	for i := range pack.Rules {
		name := strings.TrimSpace(pack.Rules[i].Name)
		if name == "" {
			return fmt.Errorf("%w: rule %d has no name", ErrInvalidPack, i+1)
		}
		if seen[name] {
			return fmt.Errorf("%w: duplicate rule name %q", ErrInvalidPack, name)
		}
		seen[name] = true
	}
	return nil
}

// ParsePack decodes one .dly JSON document. Unknown fields are rejected so a
// typo in a pack fails loudly instead of half-applying.
func ParsePack(data []byte) (Pack, error) {
	var pack Pack
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pack); err != nil {
		return Pack{}, fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Pack{}, fmt.Errorf("%w: trailing JSON data", ErrInvalidPack)
		}
		return Pack{}, fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	if err := NormalizePack(&pack); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

// BuiltinPacks lists the packs embedded in the binary. They are templates:
// importing copies their rules into the operator's catalog; the pack file
// itself is never modified.
func BuiltinPacks() ([]PackSummary, error) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	out := make([]PackSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dly") {
			continue
		}
		data, err := templateFS.ReadFile("templates/" + entry.Name())
		if err != nil {
			return nil, err
		}
		pack, err := ParsePack(data)
		if err != nil {
			return nil, fmt.Errorf("built-in pack %s: %w", entry.Name(), err)
		}
		out = append(out, pack.Summary())
	}
	return out, nil
}

// BuiltinPack returns one embedded pack by name (case-insensitive).
func BuiltinPack(name string) (Pack, error) {
	needle := strings.ToLower(strings.TrimSpace(name))
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return Pack{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dly") {
			continue
		}
		data, err := templateFS.ReadFile("templates/" + entry.Name())
		if err != nil {
			return Pack{}, err
		}
		pack, err := ParsePack(data)
		if err != nil {
			return Pack{}, fmt.Errorf("built-in pack %s: %w", entry.Name(), err)
		}
		if strings.ToLower(pack.Name) == needle {
			return pack, nil
		}
	}
	return Pack{}, fmt.Errorf("%w: no built-in pack named %q", ErrInvalidPack, name)
}

// Summary is the catalog view of the pack.
func (p Pack) Summary() PackSummary {
	names := make([]string, 0, len(p.Rules))
	for _, rule := range p.Rules {
		names = append(names, strings.TrimSpace(rule.Name))
	}
	return PackSummary{
		Name:        p.Name,
		Version:     p.Version,
		Description: p.Description,
		RuleCount:   len(p.Rules),
		RuleNames:   names,
	}
}

// ImportPack validates every rule in the pack against this store's protected
// network and adds the ones that do not already exist (same pack name and
// rule name). The import is atomic: if any rule fails validation, nothing is
// added.
func (s *Store) ImportPack(pack Pack) (ImportResult, error) {
	if err := NormalizePack(&pack); err != nil {
		return ImportResult{}, err
	}
	prepared := make([]Rule, 0, len(pack.Rules))
	for i := range pack.Rules {
		rule := pack.Rules[i]
		rule.Pack = pack.Name
		rule.ID = ""
		rule.CreatedAt = time.Time{}
		rule.UpdatedAt = time.Time{}
		rule.Stats = Stats{}
		if err := normalizeAndValidate(&rule, s.opts); err != nil {
			return ImportResult{}, fmt.Errorf("%w: rule %q: %v", ErrInvalidPack, rule.Name, err)
		}
		prepared = append(prepared, rule)
	}

	result := ImportResult{Imported: []Rule{}, Skipped: []string{}}
	now := s.clock()

	created := make([]string, 0, len(prepared))
	s.mu.Lock()
	if len(s.rules)+len(prepared) > s.opts.MaxRules {
		s.mu.Unlock()
		return ImportResult{}, fmt.Errorf("%w: importing %d rules would exceed the maximum of %d", ErrCapacity, len(prepared), s.opts.MaxRules)
	}
	existing := make(map[string]bool, len(s.rules))
	for _, rule := range s.rules {
		key := packRuleKey(rule.Pack, rule.Name)
		if key != "" {
			existing[key] = true
		}
	}
	for i := range prepared {
		rule := prepared[i]
		key := packRuleKey(rule.Pack, rule.Name)
		if existing[key] {
			result.Skipped = append(result.Skipped, rule.Name)
			continue
		}
		rule.ID = newID(now)
		for s.rules[rule.ID] != nil {
			rule.ID = newID(now)
		}
		rule.CreatedAt = now
		rule.UpdatedAt = now
		existing[key] = true
		copy := rule
		s.rules[copy.ID] = &copy
		s.order = append(s.order, copy.ID)
		s.runtime[copy.ID] = newRuntime(Stats{})
		created = append(created, copy.ID)
		view := copy
		result.Imported = append(result.Imported, view)
	}
	s.mu.Unlock()

	if len(created) == 0 {
		return result, nil
	}
	if err := s.Save(); err != nil {
		for _, id := range created {
			s.remove(id)
		}
		return ImportResult{}, err
	}
	return result, nil
}

func packRuleKey(pack, name string) string {
	pack = strings.TrimSpace(pack)
	name = strings.TrimSpace(name)
	if pack == "" || name == "" {
		return ""
	}
	return strings.ToLower(pack) + "|" + strings.ToLower(name)
}
