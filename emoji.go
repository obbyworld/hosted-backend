// IRCv3 draft/custom-emoji backend.
//
// Three concerns in one file:
//   1. SQLite schema for emoji packs + entries.
//   2. Public spec-shaped JSON documents at /emoji/pack.json and
//      /emoji/channel/{name}.json (cached 60s).
//   3. Admin REST endpoints under /emoji/admin/* gated on EXTJWT
//      umode 'o' via the existing AuthMiddleware.
//
// Wire shape (admin add-emoji):
//   POST /emoji/admin/packs/{pack_id}/emoji
//   - JSON body: {"shortcode","url","alt"} for already-hosted assets
//   - multipart body: shortcode/alt fields + file part for direct upload
//     (the file lands persistently under uploads/emoji/ so emoji never
//     auto-expire like ephemeral chat uploads do).

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// emojiUploadsDir is a separate persistent location under the global
// uploads directory.  Files in here are NOT cleaned up by the
// upload-expiry timer.  Served via the existing /uploads/ static
// handler since it lives below uploadsDir.
var emojiUploadsDir = filepath.Join(uploadsDir, "emoji")

// Shortcode validation -- mirrors the client-side regex in
// EmojiPackAdminModal so a JSON body and a multipart body both reject
// the same way.
var shortcodeRX = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var packIDRX = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// =====================================================================
// Schema
// =====================================================================

func createEmojiTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS emoji_packs (
			pack_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL CHECK (scope IN ('server','channel')),
			channel_name TEXT,
			created_by TEXT NOT NULL DEFAULT '',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_emoji_packs_scope_channel
			ON emoji_packs(scope, channel_name)`,
		`CREATE TABLE IF NOT EXISTS emoji_entries (
			pack_id TEXT NOT NULL,
			shortcode TEXT NOT NULL,
			url TEXT NOT NULL,
			alt TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (pack_id, shortcode),
			FOREIGN KEY (pack_id) REFERENCES emoji_packs(pack_id) ON DELETE CASCADE
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("emoji schema: %w", err)
		}
	}
	if err := os.MkdirAll(emojiUploadsDir, 0o755); err != nil {
		return fmt.Errorf("emoji uploads dir: %w", err)
	}
	return nil
}

// =====================================================================
// Types matching the client's emojiAdminApi
// =====================================================================

type adminPackResp struct {
	PackID      string `json:"pack_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
	ChannelName string `json:"channel_name,omitempty"`
	UpdatedAt   string `json:"updated_at"`
	EmojiCount  int    `json:"emoji_count"`
}

type createPackReq struct {
	PackID      string `json:"pack_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
	ChannelName string `json:"channel_name"`
}

type addEmojiReq struct {
	Shortcode string `json:"shortcode"`
	URL       string `json:"url"`
	Alt       string `json:"alt"`
}

// publicEntry / publicPack map to the spec's pack JSON document shape.
type publicEntry struct {
	URL string `json:"url"`
	Alt string `json:"alt,omitempty"`
}

type publicPack struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Emoji       map[string]publicEntry `json:"emoji"`
}

// =====================================================================
// Public spec endpoints
// =====================================================================

// handleEmojiPackJSON returns every server-scoped pack as a JSON array.
// Spec allows either a single object or an array; we always return an
// array so the client's resolver can iterate uniformly.
func handleEmojiPackJSON(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	packs, err := loadPublicPacks("server", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePublicPacks(w, packs)
}

func handleEmojiChannelJSON(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	channel := mux.Vars(r)["channel"]
	if channel == "" {
		http.Error(w, "channel required", http.StatusBadRequest)
		return
	}
	packs, err := loadPublicPacks("channel", channel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePublicPacks(w, packs)
}

func writePublicPacks(w http.ResponseWriter, packs []publicPack) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if packs == nil {
		packs = []publicPack{}
	}
	_ = json.NewEncoder(w).Encode(packs)
}

func loadPublicPacks(scope, channelName string) ([]publicPack, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if scope == "channel" {
		rows, err = db.Query(`SELECT pack_id, name, description
			FROM emoji_packs WHERE scope='channel' AND channel_name=?
			ORDER BY pack_id`, channelName)
	} else {
		rows, err = db.Query(`SELECT pack_id, name, description
			FROM emoji_packs WHERE scope='server'
			ORDER BY pack_id`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packs []publicPack
	for rows.Next() {
		var p publicPack
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, err
		}
		p.Emoji = map[string]publicEntry{}
		packs = append(packs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range packs {
		erows, err := db.Query(`SELECT shortcode, url, alt
			FROM emoji_entries WHERE pack_id=? ORDER BY shortcode`, packs[i].ID)
		if err != nil {
			return nil, err
		}
		for erows.Next() {
			var sc, url, alt string
			if err := erows.Scan(&sc, &url, &alt); err != nil {
				erows.Close()
				return nil, err
			}
			packs[i].Emoji[sc] = publicEntry{URL: url, Alt: alt}
		}
		erows.Close()
	}
	return packs, nil
}

// =====================================================================
// Admin endpoints (oper-only via AuthMiddleware(_, true))
// =====================================================================

func handleListPacks(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT
		p.pack_id, p.name, p.description, p.scope,
		COALESCE(p.channel_name,''), p.updated_at,
		(SELECT COUNT(*) FROM emoji_entries e WHERE e.pack_id = p.pack_id)
		FROM emoji_packs p ORDER BY p.scope, p.pack_id`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []adminPackResp{}
	for rows.Next() {
		var p adminPackResp
		var ch string
		if err := rows.Scan(&p.PackID, &p.Name, &p.Description,
			&p.Scope, &ch, &p.UpdatedAt, &p.EmojiCount); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if p.Scope == "channel" {
			p.ChannelName = ch
		}
		out = append(out, p)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleCreatePack(w http.ResponseWriter, r *http.Request) {
	var req createPackReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.PackID = strings.TrimSpace(req.PackID)
	req.Name = strings.TrimSpace(req.Name)
	req.Scope = strings.TrimSpace(req.Scope)
	req.ChannelName = strings.TrimSpace(req.ChannelName)
	if !packIDRX.MatchString(req.PackID) {
		http.Error(w, "pack_id must match [A-Za-z0-9._-]+", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if req.Scope != "server" && req.Scope != "channel" {
		http.Error(w, "scope must be 'server' or 'channel'", http.StatusBadRequest)
		return
	}
	if req.Scope == "channel" && req.ChannelName == "" {
		http.Error(w, "channel_name required for channel scope", http.StatusBadRequest)
		return
	}

	creator := nickFromContext(r)
	_, err := db.Exec(`INSERT INTO emoji_packs
		(pack_id, name, description, scope, channel_name, created_by, updated_at)
		VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, CURRENT_TIMESTAMP)`,
		req.PackID, req.Name, req.Description, req.Scope, req.ChannelName, creator)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			http.Error(w, "pack_id already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"pack_id": req.PackID})
}

func handleDeletePack(w http.ResponseWriter, r *http.Request) {
	packID := mux.Vars(r)["pack"]
	if packID == "" {
		http.Error(w, "pack_id required", http.StatusBadRequest)
		return
	}
	// CASCADE on emoji_entries clears child rows; the on-disk image
	// files are intentionally retained -- a deleted pack might still
	// have references in chat history that we don't want to break.
	res, err := db.Exec(`DELETE FROM emoji_packs WHERE pack_id=?`, packID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "no such pack", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAddEmoji accepts either JSON (URL-only) or multipart (file
// upload). The latter is what the "just upload" UX runs through.
func handleAddEmoji(w http.ResponseWriter, r *http.Request) {
	packID := mux.Vars(r)["pack"]
	if packID == "" {
		http.Error(w, "pack_id required", http.StatusBadRequest)
		return
	}
	if !packExists(packID) {
		http.Error(w, "no such pack", http.StatusNotFound)
		return
	}

	contentType := r.Header.Get("Content-Type")
	var (
		shortcode, url, alt string
		err                 error
	)
	switch {
	case strings.HasPrefix(contentType, "multipart/form-data"):
		shortcode, url, alt, err = handleEmojiUpload(w, r, packID)
		if err != nil {
			// handleEmojiUpload already wrote the response.
			return
		}
	default:
		var req addEmojiReq
		if jerr := json.NewDecoder(r.Body).Decode(&req); jerr != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		shortcode = strings.TrimSpace(req.Shortcode)
		url = strings.TrimSpace(req.URL)
		alt = strings.TrimSpace(req.Alt)
		if !shortcodeRX.MatchString(shortcode) {
			http.Error(w, "shortcode must match [A-Za-z0-9._-]+",
				http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(url, "http://") &&
			!strings.HasPrefix(url, "https://") &&
			!strings.HasPrefix(url, "data:") {
			http.Error(w, "url must be http(s):// or data:",
				http.StatusBadRequest)
			return
		}
	}

	if _, err := db.Exec(`INSERT INTO emoji_entries
		(pack_id, shortcode, url, alt) VALUES (?, ?, ?, ?)`,
		packID, shortcode, url, alt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			http.Error(w, "shortcode already exists in this pack",
				http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = db.Exec(`UPDATE emoji_packs SET updated_at=CURRENT_TIMESTAMP
		WHERE pack_id=?`, packID)

	w.WriteHeader(http.StatusNoContent)
}

// handleEmojiUpload pulls (shortcode, alt, file) out of a multipart
// form, persists the file under uploads/emoji/, and returns the new
// public URL.  Errors are written to the response.  The file is NOT
// scheduled for deletion -- emoji are durable.
func handleEmojiUpload(w http.ResponseWriter, r *http.Request, packID string) (
	shortcode, url, alt string, err error,
) {
	const maxBytes = 4 << 20 // 4MB hard cap on emoji uploads
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes*2)

	if perr := r.ParseMultipartForm(0); perr != nil {
		http.Error(w, "invalid multipart: "+perr.Error(),
			http.StatusBadRequest)
		return "", "", "", perr
	}
	shortcode = strings.TrimSpace(r.FormValue("shortcode"))
	alt = strings.TrimSpace(r.FormValue("alt"))
	if !shortcodeRX.MatchString(shortcode) {
		http.Error(w, "shortcode must match [A-Za-z0-9._-]+",
			http.StatusBadRequest)
		return "", "", "", errors.New("bad shortcode")
	}
	uploaded, header, ferr := r.FormFile("file")
	if ferr != nil {
		http.Error(w, "missing file: "+ferr.Error(),
			http.StatusBadRequest)
		return "", "", "", ferr
	}
	defer uploaded.Close()
	data, derr := io.ReadAll(io.LimitReader(uploaded, maxBytes+1))
	if derr != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return "", "", "", derr
	}
	if int64(len(data)) > maxBytes {
		http.Error(w, "emoji exceeds 4MB", http.StatusRequestEntityTooLarge)
		return "", "", "", errors.New("too large")
	}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowed := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true,
		".gif": true, ".webp": true, ".apng": true,
	}
	if !allowed[ext] {
		http.Error(w, "unsupported emoji extension (png/jpg/gif/webp/apng)",
			http.StatusUnsupportedMediaType)
		return "", "", "", errors.New("bad ext")
	}
	if verr := detectAndValidate(data, ext); verr != nil {
		http.Error(w, verr.Error(), http.StatusBadRequest)
		return "", "", "", verr
	}

	suffix, _ := randomHex(4)
	filename := fmt.Sprintf("%s-%s-%s%s",
		packID, shortcode,
		strconv.FormatInt(time.Now().UnixNano(), 10), suffix)
	// Sanitize: shortcode is regex-restricted, packID is regex-restricted,
	// so the filename can't escape uploadsDir, but be defensive anyway.
	filename = strings.ReplaceAll(filename, "/", "_")
	filename += ext

	full := filepath.Join(emojiUploadsDir, filename)
	if werr := os.WriteFile(full, data, 0o644); werr != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return "", "", "", werr
	}
	url = "/uploads/emoji/" + filename
	return shortcode, url, alt, nil
}

func handleDeleteEmoji(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	packID := v["pack"]
	shortcode := v["shortcode"]
	if packID == "" || shortcode == "" {
		http.Error(w, "pack_id and shortcode required",
			http.StatusBadRequest)
		return
	}
	res, err := db.Exec(`DELETE FROM emoji_entries
		WHERE pack_id=? AND shortcode=?`, packID, shortcode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "no such emoji", http.StatusNotFound)
		return
	}
	_, _ = db.Exec(`UPDATE emoji_packs SET updated_at=CURRENT_TIMESTAMP
		WHERE pack_id=?`, packID)
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// Helpers
// =====================================================================

func packExists(packID string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM emoji_packs WHERE pack_id=?`,
		packID).Scan(&n)
	return err == nil && n > 0
}

func nickFromContext(r *http.Request) string {
	v := r.Context().Value("jwt_claims")
	if v == nil {
		return ""
	}
	if c, ok := v.(*JWTClaims); ok {
		return c.Sub
	}
	return ""
}

// =====================================================================
// Route registration -- called from main.go
// =====================================================================

func registerEmojiRoutes(r *mux.Router) {
	if err := createEmojiTables(); err != nil {
		log.Printf("emoji: schema init failed: %v", err)
		return
	}

	// Public, unauthenticated -- the spec wants any client to be able
	// to fetch the pack.
	r.HandleFunc("/emoji/pack.json", handleEmojiPackJSON).
		Methods("GET", "OPTIONS")
	r.HandleFunc("/emoji/channel/{channel:.+}.json", handleEmojiChannelJSON).
		Methods("GET", "OPTIONS")

	// Admin endpoints under /emoji/admin/* -- AuthMiddleware enforces
	// EXTJWT signed token AND umode 'o'.
	admin := r.PathPrefix("/emoji/admin").Subrouter()
	admin.HandleFunc("/packs", AuthMiddleware(handleListPacks, true)).
		Methods("GET", "OPTIONS")
	admin.HandleFunc("/packs", AuthMiddleware(handleCreatePack, true)).
		Methods("POST", "OPTIONS")
	admin.HandleFunc("/packs/{pack}",
		AuthMiddleware(handleDeletePack, true)).
		Methods("DELETE", "OPTIONS")
	admin.HandleFunc("/packs/{pack}/emoji",
		AuthMiddleware(handleAddEmoji, true)).
		Methods("POST", "OPTIONS")
	admin.HandleFunc("/packs/{pack}/emoji/{shortcode}",
		AuthMiddleware(handleDeleteEmoji, true)).
		Methods("DELETE", "OPTIONS")
}
