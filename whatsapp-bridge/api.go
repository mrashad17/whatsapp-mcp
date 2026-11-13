package main

// REST API between the Python MCP server and this bridge, plus the file and
// path checks it relies on. This file uses only the Go standard library so it
// can be unit tested on its own (see api_test.go).
//
// Security model:
//   - The API listens on 127.0.0.1 only, never on the network.
//   - Every request needs "Authorization: Bearer <token>". The token is random,
//     created on first run and stored in store/api_token (mode 0600). The
//     Python server reads the same file.
//   - Requests must be JSON, must use a localhost Host header, and must not
//     carry a browser Origin header. Together with the token this blocks web
//     pages (CSRF, DNS rebinding) from driving the API.
//   - Files can only be sent from the outbox folder (default
//     ~/WhatsApp-MCP-Outbox, override with WHATSAPP_MCP_OUTBOX).
//   - Downloaded media file names are cleaned so a sender cannot choose where
//     a file is written.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	apiPort         = 8080
	apiTokenFile    = "api_token"
	maxRequestBytes = 1 << 20 // 1 MiB of JSON is far more than any request needs
)

// SendMessageResponse represents the response for the send message API
type SendMessageResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SendMessageRequest represents the request body for the send message API
type SendMessageRequest struct {
	Recipient string `json:"recipient"`
	Message   string `json:"message"`
	MediaPath string `json:"media_path,omitempty"`
}

// DownloadMediaRequest represents the request body for the download media API
type DownloadMediaRequest struct {
	MessageID string `json:"message_id"`
	ChatJID   string `json:"chat_jid"`
}

// DownloadMediaResponse represents the response for the download media API
type DownloadMediaResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Filename string `json:"filename,omitempty"`
	Path     string `json:"path,omitempty"`
}

// apiConfig holds what the REST API needs to authorize and check requests.
type apiConfig struct {
	Port      int
	Token     string
	OutboxDir string // absolute, symlinks resolved
}

type sendFunc func(recipient, message, mediaPath string) (bool, string)
type downloadFunc func(messageID, chatJID string) (bool, string, string, string, error)

// ensurePrivateDir creates dir if needed and makes it readable only by the
// current user.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

// restrictFile makes an existing file readable only by the current user.
// A missing file is not an error.
func restrictFile(path string) error {
	if err := os.Chmod(path, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// loadOrCreateToken returns the API token stored in storeDir, creating a new
// random one (mode 0600) on first run.
func loadOrCreateToken(storeDir string) (string, error) {
	path := filepath.Join(storeDir, apiTokenFile)
	if data, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(data))
		if len(token) >= 32 {
			if err := restrictFile(path); err != nil {
				return "", err
			}
			return token, nil
		}
		return "", fmt.Errorf("%s is too short; delete it to create a new token", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(token + "\n"); err != nil {
		return "", err
	}
	return token, nil
}

// defaultOutboxDir is the only folder files may be sent from.
func defaultOutboxDir() string {
	if dir := strings.TrimSpace(os.Getenv("WHATSAPP_MCP_OUTBOX")); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, "WhatsApp-MCP-Outbox")
}

// resolveOutbox creates the outbox folder and returns its real absolute path.
func resolveOutbox(dir string) (string, error) {
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// isInside reports whether target is base or a path below it. Both must be
// absolute and already cleaned.
func isInside(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// checkMediaPath allows a file to be sent only if, after resolving symlinks,
// it is a regular file inside the outbox folder.
func checkMediaPath(outboxDir, mediaPath string) (string, error) {
	if strings.TrimSpace(mediaPath) == "" {
		return "", errors.New("media path is empty")
	}
	abs, err := filepath.Abs(mediaPath)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("media file not found")
	}
	if !isInside(outboxDir, real) {
		return "", fmt.Errorf("files can only be sent from %s", outboxDir)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("media path is not a regular file")
	}
	return real, nil
}

// safeFileName turns a sender-supplied file name into a plain name with no
// directory parts, so it cannot point outside the folder it is saved in.
func safeFileName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r == 0 || unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimLeft(strings.TrimSpace(name), ".")
	if runes := []rune(name); len(runes) > 150 {
		ext := []rune(filepath.Ext(name))
		if len(ext) > 20 {
			ext = nil
		}
		name = string(runes[:150-len(ext)]) + string(ext)
	}
	if name == "" {
		name = "file_" + time.Now().Format("20060102_150405")
	}
	return name
}

// safeChatDirName turns a chat JID into a single folder name.
func safeChatDirName(chatJID string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '@', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, chatJID)
	name = strings.TrimLeft(name, ".")
	if name == "" {
		name = "chat"
	}
	return name
}

// joinInside joins base and name and checks that the result stays in base.
func joinInside(base, name string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	target := filepath.Join(absBase, name)
	if !isInside(absBase, target) || target == absBase {
		return "", fmt.Errorf("refusing to write outside %s", absBase)
	}
	return target, nil
}

// validRecipient accepts a phone number (digits only, 7-15 long) or a JID.
func validRecipient(r string) bool {
	if strings.Contains(r, "@") {
		return len(r) > 3 && !strings.ContainsAny(r, " /\\")
	}
	if len(r) < 7 || len(r) > 15 {
		return false
	}
	for _, c := range r {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// guard wraps a handler with the checks every API request must pass.
func guard(cfg apiConfig, next http.HandlerFunc) http.HandlerFunc {
	allowedHosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", cfg.Port): true,
		fmt.Sprintf("localhost:%d", cfg.Port): true,
	}
	want := []byte("Bearer " + cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !allowedHosts[r.Host] {
			http.Error(w, "Forbidden host", http.StatusForbidden)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "Browser requests are not allowed", http.StatusForbidden)
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if cfg.Token == "" || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// newAPIHandler builds the HTTP handler for the bridge's REST API.
func newAPIHandler(cfg apiConfig, send sendFunc, download downloadFunc) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/send", guard(cfg, func(w http.ResponseWriter, r *http.Request) {
		var req SendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}
		if !validRecipient(req.Recipient) {
			http.Error(w, "Recipient must be 7-15 digits or a JID", http.StatusBadRequest)
			return
		}
		if req.Message == "" && req.MediaPath == "" {
			http.Error(w, "Message or media path is required", http.StatusBadRequest)
			return
		}

		mediaPath := ""
		if req.MediaPath != "" {
			checked, err := checkMediaPath(cfg.OutboxDir, req.MediaPath)
			if err != nil {
				writeJSON(w, http.StatusForbidden, SendMessageResponse{Success: false, Message: err.Error()})
				return
			}
			mediaPath = checked
		}

		// Message text is deliberately not logged.
		success, message := send(req.Recipient, req.Message, mediaPath)
		fmt.Printf("Send request to %s: success=%v\n", req.Recipient, success)
		status := http.StatusOK
		if !success {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, SendMessageResponse{Success: success, Message: message})
	}))

	mux.HandleFunc("/api/download", guard(cfg, func(w http.ResponseWriter, r *http.Request) {
		var req DownloadMediaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}
		if req.MessageID == "" || req.ChatJID == "" {
			http.Error(w, "Message ID and Chat JID are required", http.StatusBadRequest)
			return
		}

		success, mediaType, filename, path, err := download(req.MessageID, req.ChatJID)
		if !success || err != nil {
			errMsg := "Unknown error"
			if err != nil {
				errMsg = err.Error()
			}
			writeJSON(w, http.StatusInternalServerError, DownloadMediaResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to download media: %s", errMsg),
			})
			return
		}
		writeJSON(w, http.StatusOK, DownloadMediaResponse{
			Success:  true,
			Message:  fmt.Sprintf("Successfully downloaded %s media", mediaType),
			Filename: filename,
			Path:     path,
		})
	}))

	return mux
}

// startRESTServer starts the REST API on 127.0.0.1 in the background.
func startRESTServer(cfg apiConfig, send sendFunc, download downloadFunc) *http.Server {
	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Handler:           newAPIHandler(cfg, send, download),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute, // media uploads can be slow
		IdleTimeout:       60 * time.Second,
	}
	fmt.Printf("Starting REST API server on %s (localhost only)...\n", srv.Addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("REST API server error: %v\n", err)
		}
	}()
	return srv
}
