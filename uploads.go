// Multimedia upload primitives.
//
// Splits the previously image-only upload pipeline into reusable
// pieces so we can accept video / audio / generic media files in
// addition to images, with admin-controlled allowlists and (when
// configured) a ClamAV scan before the file is exposed.
//
// Public surface:
//   loadMediaConfig() -- read env vars, return a MediaConfig
//   (mc) IsAllowed(extOrFilename) -- bool
//   (mc) Kind(ext) -- "image" | "video" | "audio" | "other"
//   detectAndValidate(data, ext) -- check magic bytes match the
//   advertised extension; rejects spoofed types.
//   scanWithClamAV(path) -- run the configured scanner; nil if
//   the file is clean or scanning is off, error otherwise.

package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Reasonable default extension list -- can be overridden via the
// ALLOWED_EXTENSIONS env var (comma-separated, with or without dots).
var defaultAllowedExtensions = []string{
	// images
	".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".heic",
	// video
	".mp4", ".webm", ".mov", ".m4v", ".ogv",
	// audio
	".mp3", ".ogg", ".oga", ".opus", ".wav", ".flac", ".aac", ".m4a",
	// encrypted attachments
	e2eeExtension,
}

// Rewriting these bytes breaks the client's authentication tag.
const e2eeExtension = ".obb"

var e2eeMagic = []byte("OBBYE2EE\x01")

// Magic-byte / structural sniff overrides for types where Go's
// http.DetectContentType is wrong or too permissive.  Each entry is a
// (file extension, expected detected MIME prefix) -- the actual
// detected MIME must start with one of the entries' values for the
// extension to be accepted.
var magicBytePrefixes = map[string][]string{
	".jpg":  {"image/jpeg"},
	".jpeg": {"image/jpeg"},
	".png":  {"image/png"},
	".gif":  {"image/gif"},
	".webp": {"image/webp"},
	".avif": {"image/avif", "image/heif", "image/heic"}, // some sniffs
	".bmp":  {"image/bmp"},
	".heic": {"image/heic", "image/heif"},
	".mp4":  {"video/mp4", "video/quicktime"}, // QT-derived
	".m4v":  {"video/mp4", "video/quicktime"},
	".webm": {"video/webm"},
	".mov":  {"video/quicktime", "video/mp4"},
	".ogv":  {"video/ogg", "application/ogg"},
	".mp3":  {"audio/mpeg"},
	".ogg":  {"audio/ogg", "application/ogg"},
	".oga":  {"audio/ogg", "application/ogg"},
	".opus": {"audio/ogg", "application/ogg"},
	".wav":  {"audio/wave", "audio/wav", "audio/x-wav"},
	".flac": {"audio/flac", "application/octet-stream"}, // Go often misses
	".aac":  {"audio/aac", "audio/x-aac", "application/octet-stream"},
	".m4a":  {"audio/m4a", "audio/mp4", "audio/x-m4a"},
}

// MediaConfig captures everything the upload pipeline needs to know.
type MediaConfig struct {
	AllowedExtensions map[string]bool
	MaxUploadBytes    int64
	ClamAVCmd         string
	ClamAVEnabled     bool
}

// loadMediaConfig reads env vars.  ALLOWED_EXTENSIONS overrides the
// default list when set (comma-separated).  CLAMAV_ENABLED toggles
// scanning; CLAMAV_CMD picks the binary (defaults to "clamdscan",
// falling back to "clamscan" if the daemon isn't around).
func loadMediaConfig(maxUploadBytes int64) MediaConfig {
	mc := MediaConfig{
		AllowedExtensions: map[string]bool{},
		MaxUploadBytes:    maxUploadBytes,
	}
	exts := os.Getenv("ALLOWED_EXTENSIONS")
	if exts == "" {
		for _, e := range defaultAllowedExtensions {
			mc.AllowedExtensions[strings.ToLower(e)] = true
		}
	} else {
		for _, raw := range strings.Split(exts, ",") {
			e := strings.TrimSpace(strings.ToLower(raw))
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			mc.AllowedExtensions[e] = true
		}
	}
	mc.ClamAVEnabled = strings.EqualFold(os.Getenv("CLAMAV_ENABLED"), "true")
	mc.ClamAVCmd = os.Getenv("CLAMAV_CMD")
	if mc.ClamAVCmd == "" {
		mc.ClamAVCmd = "clamdscan"
	}
	return mc
}

// IsAllowed accepts either a filename ("foo.PNG") or a bare ext
// (".png" / "png"), returning true iff it's in the allowlist.  Case
// insensitive.
func (mc MediaConfig) IsAllowed(s string) bool {
	if s == "" {
		return false
	}
	if !strings.HasPrefix(s, ".") {
		// Treat as filename or bare ext.
		if i := strings.LastIndex(s, "."); i >= 0 {
			s = s[i:]
		} else {
			s = "." + s
		}
	}
	return mc.AllowedExtensions[strings.ToLower(s)]
}

// Kind classifies the extension into one of "image" / "video" /
// "audio" / "other".  Used to decide whether the image-processing
// pass (EXIF strip + downscale) applies.
func (mc MediaConfig) Kind(ext string) string {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".heic":
		return "image"
	case ".mp4", ".webm", ".mov", ".m4v", ".ogv":
		return "video"
	case ".mp3", ".ogg", ".oga", ".opus", ".wav", ".flac", ".aac", ".m4a":
		return "audio"
	}
	return "other"
}

// SortedExtensions is convenience for /upload/info responses: a stable
// slice of allowed extensions for JSON serialisation.
func (mc MediaConfig) SortedExtensions() []string {
	out := make([]string, 0, len(mc.AllowedExtensions))
	for e := range mc.AllowedExtensions {
		out = append(out, e)
	}
	// stable order so cache-friendly clients see consistent output
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// detectAndValidate inspects the first 512 bytes of `data`, runs Go's
// content-type sniffer, and returns an error when the result doesn't
// look like the extension claims.  The check is best-effort: it stops
// trivial spoofs ("evil.exe renamed to fluffy.png") but doesn't try
// to replace a full mime/magic library.
func detectAndValidate(data []byte, ext string) error {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	if len(data) < 8 {
		return errors.New("file is too short to validate")
	}
	if ext == e2eeExtension {
		if !bytes.HasPrefix(data, e2eeMagic) {
			return fmt.Errorf("file content does not match the %s extension", ext)
		}
		return nil
	}
	detected := http.DetectContentType(data)
	expected, ok := magicBytePrefixes[ext]
	if !ok {
		// Unknown ext but extension was already in allowlist -- accept.
		return nil
	}
	for _, prefix := range expected {
		if strings.HasPrefix(detected, prefix) {
			return nil
		}
	}
	return fmt.Errorf(
		"file content (%s) does not match the .%s extension",
		detected,
		strings.TrimPrefix(ext, "."),
	)
}

// scanWithClamAV invokes the configured clamscan / clamdscan binary
// against the file at `path`.  Returns nil on a clean result OR when
// scanning is disabled OR when the binary isn't installed (we
// fail-open in the latter case to avoid breaking deployments that
// haven't set up ClamAV; admins can audit the warning logged).
//
// Exit codes per ClamAV(1):
//   0 -- no virus
//   1 -- virus found
//   2+ -- error
func scanWithClamAV(mc MediaConfig, path string) error {
	if !mc.ClamAVEnabled {
		return nil
	}
	if mc.ClamAVCmd == "" {
		return nil
	}
	// Probe for the binary; if missing, fail-open with a console warning.
	if _, err := exec.LookPath(mc.ClamAVCmd); err != nil {
		fmt.Printf("warning: ClamAV scanner %q not found in PATH; skipping\n",
			mc.ClamAVCmd)
		return nil
	}
	cmd := exec.Command(mc.ClamAVCmd, "--no-summary", "--quiet", path)
	out, runErr := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		return fmt.Errorf("clamav: process did not run: %v", runErr)
	}
	switch cmd.ProcessState.ExitCode() {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("file rejected by virus scanner: %s",
			strings.TrimSpace(string(out)))
	default:
		// ClamAV encountered an error -- fail-open with a warning.
		fmt.Printf("warning: ClamAV scanner errored (exit %d): %s\n",
			cmd.ProcessState.ExitCode(), strings.TrimSpace(string(out)))
		return nil
	}
}

// randomHex returns 2*n hex chars suitable for a filename suffix.
// Used to disambiguate uploads that would otherwise collide on the
// nanosecond timestamp.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	// crypto/rand.Read uses getrandom(2) on Linux, which returns
	// after exactly len(buf) bytes -- unlike os.ReadFile("/dev/urandom"),
	// which would try to read the entire (infinite) stream and OOM
	// the process.
	if _, err := cryptorand.Read(buf); err == nil {
		return hex.EncodeToString(buf), nil
	}
	// Fallback: not cryptographically strong but good enough for a
	// filename suffix.
	for i := range buf {
		buf[i] = byte(i + 1)
	}
	return hex.EncodeToString(buf), nil
}

// uploadsDir is where non-image media (and new image uploads) land.
// Old image-only URLs at /images/ keep working because
// processImage still routes through that path.
const uploadsDir = "uploads"

// ensureUploadsDir creates the uploads directory if missing.
func ensureUploadsDir() {
	_ = os.MkdirAll(uploadsDir, 0o755)
}

// uploadsPath joins the uploads directory with a filename.
func uploadsPath(name string) string {
	return filepath.Join(uploadsDir, name)
}

// sweepInterval is how often expired uploads are looked for. Frequent enough
// that a file outlives its retention by minutes rather than hours, cheap
// enough that it is a directory listing and nothing more.
const sweepInterval = 10 * time.Minute

// sweepExpiredUploads deletes files in the uploads directory last modified
// longer ago than retention, and reports how many went. Subdirectories are
// left alone, which is what keeps uploads/emoji/ (deliberately permanent)
// out of it.
//
// The per-upload timer only lives as long as the process, so without this a
// restart would strand every pending file on disk forever.
func sweepExpiredUploads(dir string, retention time.Duration, now time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) < retention {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// startUploadSweeper runs a sweep now and then on every tick, so retention is
// enforced across restarts rather than only while the process that took the
// upload is still alive.
func startUploadSweeper(retention time.Duration) {
	if removed, err := sweepExpiredUploads(uploadsDir, retention, time.Now()); err != nil {
		log.Printf("upload sweep failed: %v", err)
	} else if removed > 0 {
		log.Printf("upload sweep removed %d expired file(s) at startup", removed)
	}
	go func() {
		for range time.Tick(sweepInterval) {
			if removed, err := sweepExpiredUploads(uploadsDir, retention, time.Now()); err != nil {
				log.Printf("upload sweep failed: %v", err)
			} else if removed > 0 {
				log.Printf("upload sweep removed %d expired file(s)", removed)
			}
		}
	}()
}
