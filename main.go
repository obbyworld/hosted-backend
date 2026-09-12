package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"backend/orca"

	"github.com/disintegration/imaging"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type UploadRequest struct {
	URL string `json:"url"`
}

type UploadResponse struct {
	SavedURL string `json:"saved_url"`
}

func corsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// setCORSHeaders sets comprehensive CORS headers for API endpoints
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
}

// processImage processes images based on configuration
func processImage(data []byte, author string, jwtExpiry time.Time, serverExpiry time.Time, compressionEnabled bool, maxWidth, maxHeight, jpegQuality int, convertToJpeg bool) ([]byte, string, error) {
	// Decode image
	img, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", err
	}

	processed := false

	// Apply compression if enabled
	if compressionEnabled {
		// Resize to fit within configured dimensions
		img = imaging.Fit(img, maxWidth, maxHeight, imaging.Lanczos)
		processed = true
	}

	// Encode based on configuration
	buf := new(bytes.Buffer)

	if convertToJpeg || format == "jpeg" || processed {
		// Convert to JPEG
		err = jpeg.Encode(buf, img, &jpeg.Options{Quality: jpegQuality})
		if err != nil {
			return nil, "", err
		}

		encoded := buf.Bytes()

		// Add metadata as JPEG comment (author format: nick:account)
		metadata := map[string]string{
			"author":       author,
			"jwt_expiry":   jwtExpiry.Format(time.RFC3339),
			"server_expiry": serverExpiry.Format(time.RFC3339),
		}
		commentBytes, err := json.Marshal(metadata)
		if err != nil {
			// Fallback to plain text if JSON marshaling fails
			comment := "Author: " + author + "; JWT Expires: " + jwtExpiry.Format(time.RFC3339) + "; Server Expires: " + serverExpiry.Format(time.RFC3339)
			commentBytes = []byte(comment)
		}

		// Insert COM segment after SOI (FF D8)
		if len(encoded) >= 2 {
			comMarker := []byte{0xFF, 0xFE}
			length := uint16(len(commentBytes) + 2) // +2 for length field
			lengthBytes := []byte{byte(length >> 8), byte(length)}
			comSegment := append(comMarker, lengthBytes...)
			comSegment = append(comSegment, commentBytes...)

			// Insert after SOI
			result := make([]byte, 0, len(encoded)+len(comSegment))
			result = append(result, encoded[:2]...)
			result = append(result, comSegment...)
			result = append(result, encoded[2:]...)
			return result, "jpeg", nil
		}

		return encoded, "jpeg", nil
	} else {
		// Keep original format (PNG, GIF, etc.)
		switch format {
		case "png":
			err = imaging.Encode(buf, img, imaging.PNG)
		case "gif":
			err = imaging.Encode(buf, img, imaging.GIF)
		default:
			// Fallback to JPEG
			err = jpeg.Encode(buf, img, &jpeg.Options{Quality: jpegQuality})
		}
		if err != nil {
			return nil, "", err
		}
		return buf.Bytes(), format, nil
	}
}


func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: Error loading .env file: %v\n", err)
	}

	// Create images directory if it doesn't exist
	os.MkdirAll("images", os.ModePerm)

	// Read port from environment variable, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// How long an uploaded file stays reachable. Two hours gives a reader time
	// to open what was shared while a conversation is still going.
	deleteTimeoutStr := os.Getenv("DELETE_TIMEOUT_MINUTES")
	deleteTimeoutMinutes := 120
	if deleteTimeoutStr != "" {
		if parsed, err := strconv.Atoi(deleteTimeoutStr); err == nil {
			deleteTimeoutMinutes = parsed
		}
	}
	deleteTimeout := time.Duration(deleteTimeoutMinutes) * time.Minute

	// Read max upload size from environment variable, default to 100MB
	// (videos and audio routinely exceed the old 32MB ceiling).
	maxUploadSizeStr := os.Getenv("MAX_UPLOAD_SIZE_MB")
	maxUploadSizeMB := 100
	if maxUploadSizeStr != "" {
		if parsed, err := strconv.Atoi(maxUploadSizeStr); err == nil {
			maxUploadSizeMB = parsed
		}
	}
	maxUploadSize := int64(maxUploadSizeMB) << 20

	// Multimedia config: allowed extensions, ClamAV scanning, etc.
	mediaCfg := loadMediaConfig(maxUploadSize)
	ensureUploadsDir()

	// Read image processing configuration
	imageCompressionEnabled := os.Getenv("IMAGE_COMPRESSION_ENABLED") == "true"
	imageMaxWidth := 1920
	if widthStr := os.Getenv("IMAGE_MAX_WIDTH"); widthStr != "" {
		if parsed, err := strconv.Atoi(widthStr); err == nil && parsed > 0 {
			imageMaxWidth = parsed
		}
	}
	imageMaxHeight := 1080
	if heightStr := os.Getenv("IMAGE_MAX_HEIGHT"); heightStr != "" {
		if parsed, err := strconv.Atoi(heightStr); err == nil && parsed > 0 {
			imageMaxHeight = parsed
		}
	}
	imageJpegQuality := 85
	if qualityStr := os.Getenv("IMAGE_JPEG_QUALITY"); qualityStr != "" {
		if parsed, err := strconv.Atoi(qualityStr); err == nil && parsed > 0 && parsed <= 100 {
			imageJpegQuality = parsed
		}
	}
	imageConvertToJpeg := os.Getenv("IMAGE_CONVERT_TO_JPEG") == "true"

	// Initialize database
	if err := InitDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}

	// Initialize IRC connection
	if err := InitIRCConn(); err != nil {
		fmt.Printf("Failed to connect to IRC: %v\n", err)
		// Continue without IRC features
	}

	// Web Push (soju.im/webpush): load/generate the VAPID keypair so
	// /push/vapid-key and /push/send can serve obbyircd.
	if err := InitWebPush(); err != nil {
		fmt.Printf("Failed to initialize web push: %v\n", err)
		// Continue without push features
	}

	// Voice subsystem: embedded TURN + WebRTC SFU + Unix-socket
	// bridge for obbyircd's voice-channels module.  No-ops with a
	// log line if VOICE_TURN_SECRET is unset.
	voiceCtx, voiceCancel := context.WithCancel(context.Background())
	voiceMgr, voiceShutdown := startVoiceSubsystem(voiceCtx)
	defer func() {
		voiceCancel()
		voiceShutdown()
	}()

	orcaCtx, orcaCancel := context.WithCancel(context.Background())
	defer orcaCancel()
	var orcaVoice orca.LocalParticipantAPI
	if voiceMgr != nil {
		orcaVoice = voiceAPIAdapter{mgr: voiceMgr}
	}
	if _, err := orca.Start(orcaCtx, ircAdapter{}, orcaVoice); err != nil {
		fmt.Printf("orca: %v\n", err)
	}

	r := mux.NewRouter()

	// OAuth2 token-endpoint CORS proxy. Browsers can't POST directly to
	// GitHub's /login/oauth/access_token (no Allow-Origin header). The
	// SPA hits POST /oauth/exchange/<provider> here and we relay to the
	// upstream URL configured via OAUTH_PROXY_<PROVIDER> in .env.
	r.HandleFunc("/oauth/exchange/{provider}", handleOAuthExchange).
		Methods("POST", "OPTIONS")

	// File upload (requires a draft/authtoken bearer minted by
	// obbyircd's `TOKEN GENERATE filehost`).  AuthTokenMiddleware
	// burns the token on validate -- one upload per token, matching
	// the spec's single-use semantic.
	r.HandleFunc("/upload", AuthTokenMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadHandler(w, r, port, deleteTimeout, mediaCfg, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	})).Methods("POST", "OPTIONS")

	// Public upload-policy discovery so clients can pre-validate
	// before pushing bytes.  No auth required: the policy is the
	// same for every authenticated caller, and the values are not
	// secret.
	r.HandleFunc("/upload/info", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"max_size":           mediaCfg.MaxUploadBytes,
			"allowed_extensions": mediaCfg.SortedExtensions(),
			"scanning_enabled":   mediaCfg.ClamAVEnabled,
		})
	}).Methods("GET", "OPTIONS")

	// Avatar uploads — same draft/authtoken flow as /upload.
	r.HandleFunc("/upload/avatar/user", AuthTokenMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadUserAvatarHandler(w, r, maxUploadSize, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	})).Methods("POST", "OPTIONS")

	r.HandleFunc("/upload/avatar/channel/{channel}", AuthTokenMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadChannelAvatarHandler(w, r, maxUploadSize, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	})).Methods("POST", "OPTIONS")

	// Image serving (kept for back-compat with old links)
	r.PathPrefix("/images/").Handler(corsHandler(http.StripPrefix("/images/", http.FileServer(http.Dir("images")))))
	// Generic media serving (videos, audio, and new image uploads)
	r.PathPrefix("/uploads/").Handler(corsHandler(http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadsDir)))))

	// draft/custom-emoji: public pack JSON + admin CRUD (oper-only).
	registerEmojiRoutes(r)

	// IRC info endpoints (require JWT + IRCop)
	r.HandleFunc("/irc/users", AuthMiddleware(handleIRCUsers, true)).Methods("GET")
	r.HandleFunc("/irc/channels", AuthMiddleware(handleIRCChannels, true)).Methods("GET")
	r.HandleFunc("/irc/bans", AuthMiddleware(handleIRCBans, true)).Methods("GET")
	r.HandleFunc("/irc/stats", AuthMiddleware(handleIRCStats, true)).Methods("GET")
	r.HandleFunc("/irc/server-uptime", AuthMiddleware(handleIRCServerUptime, true)).Methods("GET")

	// Account management (require server key)
	accountRouter := r.PathPrefix("/irc/accounts").Subrouter()
	accountRouter.Use(ServerAuthMiddleware)
	accountRouter.HandleFunc("/register", handleRegisterAccount).Methods("POST")
	accountRouter.HandleFunc("/login", handleLogin).Methods("POST")
	accountRouter.HandleFunc("/{id}", handleGetAccount).Methods("GET")
	accountRouter.HandleFunc("/{id}", handleUpdateAccount).Methods("PUT")
	accountRouter.HandleFunc("/{id}/metadata", handleSetUserMetadata).Methods("POST")
	accountRouter.HandleFunc("/verify/{code}", handleVerifyEmail).Methods("GET")

	// Channel management (require server key)
	channelRouter := r.PathPrefix("/irc/channels").Subrouter()
	channelRouter.Use(ServerAuthMiddleware)
	channelRouter.HandleFunc("/register", handleRegisterChannel).Methods("POST")
	channelRouter.HandleFunc("/{id}", handleGetChannel).Methods("GET")
	channelRouter.HandleFunc("/{id}", handleUpdateChannel).Methods("PUT")
	channelRouter.HandleFunc("/{id}/metadata", handleSetChannelMetadata).Methods("POST")
	channelRouter.HandleFunc("/{id}/permissions", handleSetChannelPermissions).Methods("POST")

	// Web Push: VAPID public key is non-secret (clients embed it, obbyircd
	// advertises it in ISUPPORT), so the key endpoint is unauthenticated.
	r.HandleFunc("/push/vapid-key", handleVapidKey).Methods("GET", "OPTIONS")
	// The send endpoint is obbyircd-only -- guarded by the shared
	// X-ObsidianIRC-Key (same secret the /irc/* server routes use).
	pushRouter := r.PathPrefix("/push").Subrouter()
	pushRouter.Use(ServerAuthMiddleware)
	pushRouter.HandleFunc("/send", handlePushSend).Methods("POST")

	// pprof on loopback only -- useful for diagnosing runaway memory
	// without exposing it externally.  curl 127.0.0.1:6060/debug/pprof/heap
	go func() {
		_ = http.ListenAndServe("127.0.0.1:6060", nil)
	}()

	fmt.Printf("Server starting on :%s\n", port)
	http.ListenAndServe(":"+port, r)
}

func uploadHandler(w http.ResponseWriter, r *http.Request, port string, deleteTimeout time.Duration, mediaCfg MediaConfig, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Author info from the auth middleware -- carried forward into
	// EXIF strip / image-processing for parity with the old behaviour.
	claims := r.Context().Value("jwt_claims").(*JWTClaims)
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account
	jwtExpiry := time.Unix(claims.Exp, 0)
	expiry := time.Now().Add(deleteTimeout)

	// Pull the upload's bytes + filename out of whichever content
	// type the client used.  We accept the modern multipart form
	// ("file" or legacy "image" field), raw image bodies, and JSON
	// URL pulls.
	var (
		data        []byte
		filename    string
		contentType = r.Header.Get("Content-Type")
	)

	// Hard cap the request body up front. ParseMultipartForm's
	// "maxMemory" arg is only the RAM/disk-spill threshold, not a
	// total body limit -- without this guard a runaway upload (or an
	// attacker) reads the entire body and OOMs the process before the
	// post-parse size check can ever fire.  We allow ~2x the file
	// limit + a small header budget to cover the dual "file" + "image"
	// form fields the multimedia client posts.
	bodyLimit := mediaCfg.MaxUploadBytes*2 + 1<<20
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)

	switch {
	case strings.Contains(contentType, "multipart/form-data"):
		// maxMemory = 0 forces every part to spill to a temp file
		// after Go's internal 10MB threshold, so we never hold the
		// whole upload in memory. Without this, bytes.Buffer.grow()
		// doubles capacity per file part (and the multimedia client
		// posts the same file *twice* under "file" and "image"),
		// turning a 100MB upload into ~800MB of transient heap.
		if err := r.ParseMultipartForm(0); err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		field := "file"
		uploaded, header, err := r.FormFile(field)
		if err != nil {
			// Back-compat: old clients use "image".
			field = "image"
			uploaded, header, err = r.FormFile(field)
			if err != nil {
				http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		defer uploaded.Close()
		filename = header.Filename
		data, err = io.ReadAll(uploaded)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}
	case strings.HasPrefix(contentType, "image/"):
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mediaCfg.MaxUploadBytes))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		// Pick a sensible extension from the MIME so allowlist / magic
		// validation has something to check against.
		filename = "raw" + extFromMime(contentType)
		data = body
	case strings.Contains(contentType, "application/json"):
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(req.URL)
		if err != nil || resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download upload", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, mediaCfg.MaxUploadBytes))
		if err != nil {
			http.Error(w, "Failed to read downloaded upload", http.StatusInternalServerError)
			return
		}
		filename = filepath.Base(req.URL)
		data = body
	default:
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}

	if int64(len(data)) > mediaCfg.MaxUploadBytes {
		http.Error(w, "Upload exceeds the configured size limit",
			http.StatusRequestEntityTooLarge)
		return
	}

	// Allowlist + magic-byte check before we touch the disk.
	ext := strings.ToLower(filepath.Ext(filename))
	if !mediaCfg.IsAllowed(ext) {
		http.Error(w,
			"File extension not allowed (see GET /upload/info)",
			http.StatusUnsupportedMediaType)
		return
	}
	if err := detectAndValidate(data, ext); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Two save paths: images go through the existing EXIF strip +
	// resize pipeline (which may rewrite to a different output
	// extension), everything else lands on disk untouched.
	var (
		savedPath string
		savedURL  string
	)
	if mediaCfg.Kind(ext) == "image" {
		processed, format, err := processImage(data, author, jwtExpiry, expiry,
			imageCompressionEnabled, imageMaxWidth, imageMaxHeight,
			imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}
		suffix, _ := randomHex(4)
		filename := strconv.FormatInt(time.Now().UnixNano(), 10) +
			"-" + suffix + "." + format
		savedPath = uploadsPath(filename)
		if err := os.WriteFile(savedPath, processed, 0o644); err != nil {
			http.Error(w, "Failed to save upload", http.StatusInternalServerError)
			return
		}
		savedURL = "/uploads/" + filename
	} else {
		suffix, _ := randomHex(4)
		filename := strconv.FormatInt(time.Now().UnixNano(), 10) +
			"-" + suffix + ext
		savedPath = uploadsPath(filename)
		if err := os.WriteFile(savedPath, data, 0o644); err != nil {
			http.Error(w, "Failed to save upload", http.StatusInternalServerError)
			return
		}
		savedURL = "/uploads/" + filename
	}

	// Optional virus scan after the file is on disk -- the scanner
	// needs a path it can read and we want the same scrubber for
	// uploads regardless of how they got here (form, raw body, URL).
	if err := scanWithClamAV(mediaCfg, savedPath); err != nil {
		_ = os.Remove(savedPath)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	time.AfterFunc(deleteTimeout, func() {
		_ = os.Remove(savedPath)
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(UploadResponse{SavedURL: savedURL})
}

// extFromMime maps a few common image MIME types to file extensions.
// Anything we don't recognise gets ".bin", which the allowlist will
// reject -- that's the desired outcome for opaque content.
func extFromMime(mime string) string {
	mime = strings.ToLower(mime)
	switch {
	case strings.HasPrefix(mime, "image/jpeg"):
		return ".jpg"
	case strings.HasPrefix(mime, "image/png"):
		return ".png"
	case strings.HasPrefix(mime, "image/gif"):
		return ".gif"
	case strings.HasPrefix(mime, "image/webp"):
		return ".webp"
	case strings.HasPrefix(mime, "image/avif"):
		return ".avif"
	case strings.HasPrefix(mime, "image/bmp"):
		return ".bmp"
	}
	return ".bin"
}

func uploadUserAvatarHandler(w http.ResponseWriter, r *http.Request, maxUploadSize int64, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	fmt.Println("uploadUserAvatarHandler called")
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims
	claims := r.Context().Value("jwt_claims").(*JWTClaims)

	// Create author string (nick:account format)
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize)
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Read image data
		data, err := io.ReadAll(uploadedFile)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if strings.HasPrefix(contentType, "image/") {
		// Raw image upload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(body, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(claims.Account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", claims.Account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if contentType == "application/json" {
		// JSON URL upload
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Download image from URL
		resp, err := http.Get(req.URL)
		if err != nil {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}

		// Read image data
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read downloaded image", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(claims.Account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", claims.Account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}

func uploadChannelAvatarHandler(w http.ResponseWriter, r *http.Request, maxUploadSize int64, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	fmt.Println("uploadChannelAvatarHandler called")
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims
	claims := r.Context().Value("jwt_claims").(*JWTClaims)

	// Check if account exists
	if claims.Account == "" {
		http.Error(w, fmt.Sprintf("Account required for avatar upload. JWT claims: sub=%s, account='%s', umodes=%v, cmodes=%v", claims.Sub, claims.Account, claims.Umodes, claims.Cmodes), http.StatusForbidden)
		return
	}

	// Check channel permissions - must have 'o', 'a', or 'q' in cmodes
	hasPermission := false
	for _, mode := range claims.Cmodes {
		if mode == "o" || mode == "a" || mode == "q" {
			hasPermission = true
			break
		}
	}
	if !hasPermission {
		http.Error(w, "Channel operator/admin/owner permission required", http.StatusForbidden)
		return
	}

	// Get channel from URL
	vars := mux.Vars(r)
	channel := vars["channel"]
	if channel == "" {
		http.Error(w, "Channel name required", http.StatusBadRequest)
		return
	}

	// Create author string (nick:account format)
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize)
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Read image data
		data, err := io.ReadAll(uploadedFile)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if strings.HasPrefix(contentType, "image/") {
		// Raw image upload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(body, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if contentType == "application/json" {
		// JSON URL upload
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Download image from URL
		resp, err := http.Get(req.URL)
		if err != nil {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}

		// Read image data
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read downloaded image", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}

func removeOldUserAvatar(account string) {
	files, err := os.ReadDir("images")
	if err != nil {
		return
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "avatar_user_"+account+"_") {
			os.Remove(filepath.Join("images", file.Name()))
		}
	}
}

func removeOldChannelAvatar(channel string) {
	files, err := os.ReadDir("images")
	if err != nil {
		return
	}

	safeChannel := strings.ReplaceAll(channel, "#", "_hash_")
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "avatar_channel_"+safeChannel+"_") {
			os.Remove(filepath.Join("images", file.Name()))
		}
	}
}
