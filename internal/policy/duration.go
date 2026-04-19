// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/marcelocantos/doit/internal/audit"
)

// DurationStats captures the observed-duration distribution for a
// command pattern identified by (Cap, Subcmd). Values are in
// milliseconds, mirroring the audit entry's duration_ms field.
type DurationStats struct {
	Cap         string    `yaml:"cap"`
	Subcmd      string    `yaml:"subcmd,omitempty"`
	SampleCount int       `yaml:"sample_count"`
	P50Ms       float64   `yaml:"p50_ms"`
	P95Ms       float64   `yaml:"p95_ms"`
	LastUpdated time.Time `yaml:"last_updated"`
}

// minSamplesForAnomaly is the minimum observation count before a
// pattern's stats are considered trustworthy enough to flag anomalies.
const minSamplesForAnomaly = 5

// anomalyFactor sets the sharpness threshold: an expected duration
// below p50/factor or above p95*factor is flagged as a sharp deviation.
const anomalyFactor = 5.0

// AggregateDurations scans audit entries and produces per-pattern
// duration statistics. Only successful, non-timed-out, non-denied
// entries contribute — timeouts and failures produce atypical durations
// that would skew the learned distribution.
//
// Grouping mirrors AnalyseL3Decisions: (Cap, Subcmd) extracted from the
// entry's Segments and Pipeline. Entries without a recognisable cap
// are skipped.
func AggregateDurations(entries []audit.Entry) []DurationStats {
	samples := make(map[groupKey][]float64)
	latest := make(map[groupKey]time.Time)

	for _, e := range entries {
		// Only successful, non-timed-out runs contribute to the
		// learned distribution. Failures and timeouts yield atypical
		// durations that would skew the percentiles. Policy-denied
		// runs never executed, so their duration is nominally zero
		// and the duration filter below naturally excludes them.
		if e.ExitCode != 0 || e.TimedOut {
			continue
		}
		if e.Duration <= 0 {
			continue
		}
		key := keyForEntry(e)
		if key.cap == "" {
			continue
		}
		samples[key] = append(samples[key], e.Duration)
		if e.Time.After(latest[key]) {
			latest[key] = e.Time
		}
	}

	var stats []DurationStats
	for key, ms := range samples {
		if len(ms) == 0 {
			continue
		}
		sort.Float64s(ms)
		stats = append(stats, DurationStats{
			Cap:         key.cap,
			Subcmd:      key.subcmd,
			SampleCount: len(ms),
			P50Ms:       percentile(ms, 0.50),
			P95Ms:       percentile(ms, 0.95),
			LastUpdated: latest[key],
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Cap != stats[j].Cap {
			return stats[i].Cap < stats[j].Cap
		}
		return stats[i].Subcmd < stats[j].Subcmd
	})
	return stats
}

// keyForEntry extracts the (cap, subcmd) key from an audit entry,
// preferring the structured Segments field but falling back to parsing
// the raw Pipeline string. Returns an empty key when no cap name can
// be recovered (e.g. placeholder entries like "<script-approval>").
func keyForEntry(e audit.Entry) groupKey {
	if len(e.Segments) > 0 && e.Segments[0] != "" {
		info := parseEntryInfo(e)
		return info.key
	}
	cap, subcmd := extractCapSubcmd(e.Pipeline)
	if cap == "" || strings.HasPrefix(cap, "<") {
		return groupKey{}
	}
	return groupKey{cap: cap, subcmd: subcmd}
}

// percentile computes the requested percentile of a pre-sorted
// ascending slice using linear interpolation between the two nearest
// samples. p must be in [0, 1].
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	pos := p * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// CheckDurationAnomaly flags a request whose declared
// expected_duration_seconds or timeout_seconds deviates sharply from
// the learned distribution. Returns nil when there is no stats entry,
// insufficient samples, or the declared expectation is consistent with
// history.
//
// The check is deliberately asymmetric and soft:
//   - If expected_duration_seconds is set, compare against both p50 and
//     p95. A declaration below p50/factor or above p95*factor is
//     considered sharply off. This catches both "agent thinks this is
//     instant" (probably wrong) and "agent is way over-estimating"
//     (probably a misread of what the command does).
//   - If timeout_seconds is set and is below p50 (i.e. we'd likely kill
//     a normal run), that is also flagged — this prevents pointless
//     timeouts that won't let the command complete.
//
// The returned Result is Deny+bypassable so the user can override via
// --retry; it is not a hard stop.
func CheckDurationAnomaly(req *Request, stats *DurationStats) *Result {
	if stats == nil || stats.SampleCount < minSamplesForAnomaly {
		return nil
	}

	if req.ExpectedDurationSeconds > 0 {
		expectedMs := float64(req.ExpectedDurationSeconds) * 1000.0
		tooLow := stats.P50Ms > 0 && expectedMs < stats.P50Ms/anomalyFactor
		tooHigh := expectedMs > stats.P95Ms*anomalyFactor
		if tooLow || tooHigh {
			return &Result{
				Decision: Deny,
				Level:    2,
				Reason: fmt.Sprintf(
					"expected_duration_seconds=%d deviates sharply from learned p50=%.0fms / p95=%.0fms (n=%d; config rule, bypassable)",
					req.ExpectedDurationSeconds, stats.P50Ms, stats.P95Ms, stats.SampleCount,
				),
				RuleID:     "duration-anomaly",
				Bypassable: true,
			}
		}
	}

	if req.TimeoutSeconds > 0 && stats.P50Ms > 0 {
		timeoutMs := float64(req.TimeoutSeconds) * 1000.0
		if timeoutMs < stats.P50Ms {
			return &Result{
				Decision: Deny,
				Level:    2,
				Reason: fmt.Sprintf(
					"timeout_seconds=%d likely kills a normal run (learned p50=%.0fms; n=%d; config rule, bypassable)",
					req.TimeoutSeconds, stats.P50Ms, stats.SampleCount,
				),
				RuleID:     "timeout-too-short",
				Bypassable: true,
			}
		}
	}

	return nil
}

// DefaultDurationStorePath returns the default on-disk location for
// learned duration statistics.
func DefaultDurationStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "doit", "duration-stats.yaml")
}

// DurationStore persists and retrieves per-pattern duration statistics.
// Safe for concurrent use within a single process; atomic replace
// protects against partial writes across processes.
type DurationStore struct {
	path string
	mu   sync.RWMutex
	// cached is populated on first read and refreshed by Save/Replace.
	cached []DurationStats
	loaded bool
}

type durationFile struct {
	Stats []DurationStats `yaml:"stats"`
}

// NewDurationStore returns a store backed by path. Empty path uses the
// default. The file need not yet exist.
func NewDurationStore(path string) *DurationStore {
	if path == "" {
		path = DefaultDurationStorePath()
	}
	return &DurationStore{path: path}
}

// Path returns the backing file path.
func (s *DurationStore) Path() string { return s.path }

// Load reads the stats from disk. Returns an empty slice if the file
// does not yet exist.
func (s *DurationStore) Load() ([]DurationStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *DurationStore) loadLocked() ([]DurationStats, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.cached = nil
			s.loaded = true
			return nil, nil
		}
		return nil, fmt.Errorf("read duration store: %w", err)
	}
	var df durationFile
	if err := yaml.Unmarshal(data, &df); err != nil {
		return nil, fmt.Errorf("parse duration store %s: %w", s.path, err)
	}
	s.cached = df.Stats
	s.loaded = true
	return df.Stats, nil
}

// Replace writes the full list of stats, replacing any existing file.
func (s *DurationStore) Replace(stats []DurationStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveLocked(stats); err != nil {
		return err
	}
	s.cached = stats
	s.loaded = true
	return nil
}

func (s *DurationStore) saveLocked(stats []DurationStats) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create duration store dir: %w", err)
	}
	data, err := yaml.Marshal(durationFile{Stats: stats})
	if err != nil {
		return fmt.Errorf("marshal duration store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".duration-stats-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp duration file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp duration file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp duration file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp duration file: %w", err)
	}
	return nil
}

// Lookup returns the stats for a given cap+subcmd, or nil when there
// is no entry. Uses the cached copy if already loaded.
func (s *DurationStore) Lookup(cap, subcmd string) (*DurationStats, error) {
	s.mu.RLock()
	if s.loaded {
		result := findStats(s.cached, cap, subcmd)
		s.mu.RUnlock()
		return result, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			return nil, err
		}
	}
	return findStats(s.cached, cap, subcmd), nil
}

func findStats(all []DurationStats, cap, subcmd string) *DurationStats {
	for i := range all {
		if all[i].Cap == cap && all[i].Subcmd == subcmd {
			result := all[i]
			return &result
		}
	}
	return nil
}

// LookupForCommand parses the leading cap/subcmd out of a command
// string and returns any stats keyed by them. Convenience wrapper.
func (s *DurationStore) LookupForCommand(command string) (*DurationStats, error) {
	cap, subcmd := extractCapSubcmd(command)
	if cap == "" {
		return nil, nil
	}
	return s.Lookup(cap, subcmd)
}

// extractCapSubcmd mirrors parseEntryInfo's notion of cap/subcmd but
// operates on a raw command string instead of a parsed audit entry.
func extractCapSubcmd(command string) (string, string) {
	words := strings.Fields(command)
	if len(words) == 0 {
		return "", ""
	}
	cap := words[0]
	subcmd := ""
	if len(words) >= 2 && !strings.HasPrefix(words[1], "-") {
		subcmd = words[1]
	}
	return cap, subcmd
}
