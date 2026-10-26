// Package blocklist loads deterministic source blocklists from disk and
// supports an operator-managed manual list. Reloads swap an immutable snapshot
// atomically, so there is never a moment where the active list is empty.
package blocklist

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/netutil"
)

var (
	ErrInvalidEntry = errors.New("invalid blocklist entry")
	ErrProtected    = errors.New("entry overlaps a protected prefix")
	ErrExists       = errors.New("entry is already in the manual blocklist")
	ErrNotFound     = errors.New("entry is not in the manual blocklist")
	ErrDefaultRoute = errors.New("default routes are not allowed in a blocklist")
)

// FileInfo describes one loaded source file for the dashboard.
type FileInfo struct {
	Name     string    `json:"name"`
	Entries  int       `json:"entries"`
	Manual   bool      `json:"manual"`
	Error    string    `json:"error,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
}

// Entry is a single normalised blocklist prefix.
type Entry struct {
	Prefix netip.Prefix
	Source string
}

type snapshot struct {
	loadedAt   time.Time
	entries    []Entry
	exact      map[netip.Addr]Entry
	prefixes   []Entry
	files      []FileInfo
	warnings   []string
	manual     []string
	manualPath string
}

// List is a concurrent, atomically reloadable blocklist.
type List struct {
	dir       string
	manual    string
	protected *netutil.PrefixSet
	mu        sync.Mutex
	state     atomic.Pointer[snapshot]
}

// New creates a blocklist rooted at dir. The manual file lives inside dir.
func New(dir, manualFile string, protected *netutil.PrefixSet) *List {
	if manualFile == "" {
		manualFile = "manual.txt"
	}
	l := &List{
		dir:       dir,
		manual:    filepath.Join(dir, manualFile),
		protected: protected,
	}
	empty := &snapshot{
		loadedAt:   time.Now(),
		exact:      map[netip.Addr]Entry{},
		manualPath: l.manual,
	}
	l.state.Store(empty)
	return l
}

// Reload reads every regular file in the directory plus the manual file and
// swaps the result in atomically. Invalid lines are skipped and reported as
// warnings. A file that cannot be read fails the whole reload, preserving the
// previously active snapshot.
func (l *List) Reload() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reloadLocked()
}

func (l *List) reloadLocked() ([]string, error) {
	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return nil, fmt.Errorf("create blocklist directory: %w", err)
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("read blocklist directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	next := &snapshot{
		loadedAt:   time.Now(),
		exact:      map[netip.Addr]Entry{},
		manualPath: l.manual,
	}
	manualName := filepath.Base(l.manual)
	var warnings []string
	var errs []error
	seen := map[netip.Prefix]bool{}

	for _, dirent := range entries {
		name := dirent.Name()
		if dirent.IsDir() || strings.HasPrefix(name, ".") || name == manualName || strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(l.dir, name)
		info, err := dirent.Info()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		fileEntries, fileWarnings, err := parseFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		added := 0
		for _, raw := range fileEntries {
			prefix, err := normaliseEntry(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			entry := Entry{Prefix: prefix, Source: name}
			next.entries = append(next.entries, entry)
			if prefix.Addr().Is4() {
				if prefix.Bits() == prefix.Addr().BitLen() {
					next.exact[prefix.Addr()] = entry
				} else {
					next.prefixes = append(next.prefixes, entry)
				}
			} else {
				next.prefixes = append(next.prefixes, entry)
			}
			if l.protected != nil && l.protected.Overlaps(prefix) {
				warnings = append(warnings, fmt.Sprintf("%s: %s overlaps a protected prefix; automatic actions for it will be refused", name, prefix))
			}
			added++
		}
		warnings = append(warnings, fileWarnings...)
		next.files = append(next.files, FileInfo{Name: name, Entries: added, Modified: info.ModTime()})
	}

	manualEntries, manualWarnings, manualInfo, err := l.readManual()
	if err != nil {
		errs = append(errs, err)
	} else {
		warnings = append(warnings, manualWarnings...)
		if manualInfo != nil {
			next.files = append(next.files, *manualInfo)
		}
		next.manual = manualEntries
		for _, raw := range manualEntries {
			prefix, err := normaliseEntry(raw)
			if err != nil {
				continue
			}
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			entry := Entry{Prefix: prefix, Source: manualName}
			next.entries = append(next.entries, entry)
			if prefix.Addr().Is4() && prefix.Bits() == 32 {
				next.exact[prefix.Addr()] = entry
			} else {
				next.prefixes = append(next.prefixes, entry)
			}
			if l.protected != nil && l.protected.Overlaps(prefix) {
				warnings = append(warnings, fmt.Sprintf("%s: %s overlaps a protected prefix; automatic actions for it will be refused", manualName, prefix))
			}
		}
	}
	if len(errs) > 0 {
		return warnings, errors.Join(errs...)
	}
	sort.Slice(next.entries, func(i, j int) bool {
		return next.entries[i].Prefix.String() < next.entries[j].Prefix.String()
	})
	sort.Slice(next.prefixes, func(i, j int) bool {
		a, b := next.prefixes[i].Prefix, next.prefixes[j].Prefix
		if a.Bits() != b.Bits() {
			return a.Bits() > b.Bits()
		}
		return a.String() < b.String()
	})
	next.warnings = dedupeStrings(warnings, 100)
	l.state.Store(next)
	return next.warnings, nil
}

func (l *List) readManual() ([]string, []string, *FileInfo, error) {
	file, err := os.Open(l.manual)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read manual blocklist: %w", err)
	}
	defer file.Close()
	info, _ := file.Stat()
	values, err := parseReader(file)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read manual blocklist: %w", err)
	}
	clean := make([]string, 0, len(values))
	for _, value := range values {
		if _, err := normaliseEntry(value); err != nil {
			continue
		}
		clean = append(clean, value)
	}
	fi := &FileInfo{Name: filepath.Base(l.manual), Entries: len(clean), Manual: true}
	if info != nil {
		fi.Modified = info.ModTime()
	}
	return clean, nil, fi, nil
}

func parseFile(path string) ([]string, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	values, warnings := parseReaderWithWarnings(file)
	return values, warnings, nil
}

func parseReader(file *os.File) ([]string, error) {
	values, warnings := parseReaderWithWarnings(file)
	_ = warnings
	return values, nil
}

func parseReaderWithWarnings(file *os.File) ([]string, []string) {
	var values []string
	var warnings []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			warnings = append(warnings, fmt.Sprintf("line %d: ignoring entry containing whitespace", lineNo))
			continue
		}
		values = append(values, line)
	}
	if err := scanner.Err(); err != nil {
		warnings = append(warnings, "read warning: "+err.Error())
	}
	return values, warnings
}

func normaliseEntry(value string) (netip.Prefix, error) {
	prefix, err := netutil.ParseIPOrPrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrInvalidEntry, err)
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, ErrDefaultRoute
	}
	return prefix, nil
}

func dedupeStrings(values []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Lookup returns the matching blocklist entry for a source address.
func (l *List) Lookup(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	snap := l.state.Load()
	if snap == nil {
		return netip.Prefix{}, false
	}
	if entry, ok := snap.exact[addr]; ok {
		return entry.Prefix, true
	}
	for _, entry := range snap.prefixes {
		if entry.Prefix.Contains(addr) {
			return entry.Prefix, true
		}
	}
	return netip.Prefix{}, false
}

// Info is a read-only summary for the dashboard.
type Info struct {
	Entries    int        `json:"entries"`
	Files      []FileInfo `json:"files"`
	Warnings   []string   `json:"warnings"`
	Manual     []string   `json:"manual"`
	LoadedAt   time.Time  `json:"loaded_at"`
	ManualFile string     `json:"manual_file"`
}

// Info returns a deep copy of the current blocklist metadata.
func (l *List) Info() Info {
	snap := l.state.Load()
	if snap == nil {
		return Info{ManualFile: filepath.Base(l.manual)}
	}
	info := Info{
		Entries:    len(snap.entries),
		Files:      append([]FileInfo(nil), snap.files...),
		Warnings:   append([]string(nil), snap.warnings...),
		Manual:     append([]string(nil), snap.manual...),
		LoadedAt:   snap.loadedAt,
		ManualFile: filepath.Base(l.manual),
	}
	return info
}

// AddManual validates and appends an entry to the manual blocklist, then
// reloads the blocklist atomically.
func (l *List) AddManual(value string) error {
	prefix, err := normaliseEntry(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	if l.protected != nil && l.protected.Overlaps(prefix) {
		return fmt.Errorf("%w: %s", ErrProtected, prefix)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	snap := l.state.Load()
	for _, existing := range snap.manual {
		existingPrefix, err := normaliseEntry(existing)
		if err == nil && existingPrefix == prefix {
			return ErrExists
		}
	}
	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(l.manual, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if info, err := file.Stat(); err == nil && info.Size() == 0 {
		_, _ = fmt.Fprintln(file, "# Dolly Sensor manual blocklist - managed by the dashboard")
		_, _ = fmt.Fprintln(file, "# Lines starting with # are ignored. One IP or CIDR per line.")
	}
	if _, err := fmt.Fprintln(file, prefix.String()); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = l.reloadLocked()
	return err
}

// RemoveManual removes an entry from the manual blocklist and reloads.
func (l *List) RemoveManual(value string) error {
	prefix, err := normaliseEntry(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	snap := l.state.Load()
	remaining := make([]string, 0, len(snap.manual))
	found := false
	for _, existing := range snap.manual {
		existingPrefix, err := normaliseEntry(existing)
		if err == nil && existingPrefix == prefix {
			found = true
			continue
		}
		remaining = append(remaining, existing)
	}
	if !found {
		return ErrNotFound
	}
	var b strings.Builder
	b.WriteString("# Dolly Sensor manual blocklist - managed by the dashboard\n")
	b.WriteString("# Lines starting with # are ignored. One IP or CIDR per line.\n")
	for _, entry := range remaining {
		b.WriteString(entry)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return err
	}
	if err := atomicWrite(l.manual, []byte(b.String())); err != nil {
		return err
	}
	_, err = l.reloadLocked()
	return err
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".dolly-blocklist-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o640); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	return nil
}
