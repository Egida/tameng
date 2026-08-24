package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-COUNTERMEASURES-SAVEERROR-001 (follow-up)
//
// SaveError() shipped 2026-08-19 with zero production callers -- only its
// own test file exercised it. This left a live persistence failure (disk
// full, permission denied, etc.) completely unobservable in production: the
// error was captured correctly but never read by anything. Fix wires it into
// the existing 1-minute countermeasures ticker (extracted into
// countermeasuresTick so it's callable directly here, without waiting on a
// real ticker).

// TestCountermeasuresTick_WarnsOnPersistentSaveFailure proves a save
// failure is surfaced via log.Warn, not silently left unread.
func TestCountermeasuresTick_WarnsOnPersistentSaveFailure(t *testing.T) {
	cfg := minimalValidTestConfig()
	cfg.Countermeasures.Enabled = true
	dir := t.TempDir()
	cfg.Countermeasures.ActionLogPath = filepath.Join(dir, "defense-actions.json")

	var logBuf bytes.Buffer
	s, err := New(cfg, logger.NewWithWriter("test", &logBuf))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	// Force the next save to fail the same way save_error_test.go does:
	// block the temp-file rename target with a directory of the same name.
	tmpPath := cfg.Countermeasures.ActionLogPath + ".tmp"
	if err := os.Mkdir(tmpPath, 0755); err != nil {
		t.Fatalf("test setup failed creating blocking directory: %v", err)
	}
	s.countermeasures.TempBlock("203.0.113.50", "trigger save failure")
	if s.countermeasures.SaveError() == nil {
		t.Fatal("test setup did not actually trigger a save failure")
	}

	s.countermeasuresTick()

	if !strings.Contains(logBuf.String(), "not persisting") {
		t.Fatalf("countermeasuresTick() did not log the persistence warning; log output: %s", logBuf.String())
	}
}

// TestCountermeasuresTick_SilentWhenSaveSucceeds is a regression guard: a
// healthy countermeasures engine must not log a spurious warning every tick.
func TestCountermeasuresTick_SilentWhenSaveSucceeds(t *testing.T) {
	cfg := minimalValidTestConfig()
	cfg.Countermeasures.Enabled = true
	cfg.Countermeasures.ActionLogPath = filepath.Join(t.TempDir(), "defense-actions.json")

	var logBuf bytes.Buffer
	s, err := New(cfg, logger.NewWithWriter("test", &logBuf))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	s.countermeasures.TempBlock("203.0.113.51", "healthy save")
	s.countermeasuresTick()

	if strings.Contains(logBuf.String(), "not persisting") {
		t.Fatalf("countermeasuresTick() logged a persistence warning despite a healthy save; log output: %s", logBuf.String())
	}
}
