// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// TestAppendEntries_ConcurrentNoLostUpdates reproduces Fable-5 finding F7
// (🎯T44): AppendEntries is an unsynchronized LoadStore->append->SaveStore, so
// concurrent writers each save their own stale snapshot (last-writer-wins) and
// silently drop entries. With serialization all N entries must survive.
func TestAppendEntries_ConcurrentNoLostUpdates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	const n = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines together to maximise contention
			entry := PolicyEntry{
				ID:       fmt.Sprintf("entry-%d", i),
				Decision: "deny",
				Match:    MatchCriteria{Cap: "rm"},
			}
			if _, err := AppendEntries(path, []PolicyEntry{entry}); err != nil {
				t.Errorf("AppendEntries %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(got) != n {
		t.Fatalf("lost updates: persisted %d entries, want %d", len(got), n)
	}
}
