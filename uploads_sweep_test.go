package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAged(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestSweepExpiredUploads(t *testing.T) {
	dir := t.TempDir()
	retention := 2 * time.Hour

	fresh := filepath.Join(dir, "fresh.png")
	stale := filepath.Join(dir, "stale.png")
	writeAged(t, fresh, 30*time.Minute)
	writeAged(t, stale, 3*time.Hour)

	// Emoji are deliberately permanent, and they live in a subdirectory of
	// the uploads directory, so the sweep must not walk into it.
	emojiDir := filepath.Join(dir, "emoji")
	if err := os.Mkdir(emojiDir, 0o755); err != nil {
		t.Fatalf("mkdir emoji: %v", err)
	}
	emoji := filepath.Join(emojiDir, "party.png")
	writeAged(t, emoji, 30*24*time.Hour)

	removed, err := sweepExpiredUploads(dir, retention, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale upload survived the sweep")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh upload was swept: %v", err)
	}
	if _, err := os.Stat(emoji); err != nil {
		t.Errorf("emoji was swept: %v", err)
	}
}

func TestSweepExpiredUploadsMissingDir(t *testing.T) {
	if _, err := sweepExpiredUploads(filepath.Join(t.TempDir(), "gone"), time.Hour, time.Now()); err == nil {
		t.Fatal("expected an error for a missing uploads directory")
	}
}
