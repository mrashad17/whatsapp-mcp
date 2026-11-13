package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestAPI(t *testing.T) (http.Handler, string, *[]string) {
	t.Helper()
	outbox, err := resolveOutbox(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	var sent []string
	send := func(recipient, message, mediaPath string) (bool, string) {
		sent = append(sent, recipient+"|"+message+"|"+mediaPath)
		return true, "ok"
	}
	download := func(id, jid string) (bool, string, string, string, error) {
		return true, "image", "a.jpg", "/x/a.jpg", nil
	}
	cfg := apiConfig{Port: apiPort, Token: testToken, OutboxDir: outbox}
	return newAPIHandler(cfg, send, download), outbox, &sent
}

func doReq(h http.Handler, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestValidRequestIsAccepted(t *testing.T) {
	h, _, sent := newTestAPI(t)
	rec := doReq(h, "/api/send", `{"recipient":"201001234567","message":"hi"}`, nil)
	if rec.Code != http.StatusOK || len(*sent) != 1 {
		t.Fatalf("want 200 and one send, got %d %v", rec.Code, *sent)
	}
}

func TestRequestsWithoutProtectionAreRejected(t *testing.T) {
	body := `{"recipient":"201001234567","message":"hi"}`
	cases := map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"no token":          {func(r *http.Request) { r.Header.Del("Authorization") }, http.StatusUnauthorized},
		"wrong token":       {func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }, http.StatusUnauthorized},
		"text/plain (CSRF)": {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusUnsupportedMediaType},
		"browser origin":    {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		"rebinding host":    {func(r *http.Request) { r.Host = "evil.example:8080" }, http.StatusForbidden},
		"GET":               {func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, _, sent := newTestAPI(t)
			rec := doReq(h, "/api/send", body, tc.mutate)
			if rec.Code != tc.want {
				t.Fatalf("want %d, got %d", tc.want, rec.Code)
			}
			if len(*sent) != 0 {
				t.Fatalf("message was sent despite rejection")
			}
		})
	}
}

func TestSendFileOnlyFromOutbox(t *testing.T) {
	h, outbox, sent := newTestAPI(t)

	inside := filepath.Join(outbox, "photo.jpg")
	os.WriteFile(inside, []byte("x"), 0600)
	outside := filepath.Join(t.TempDir(), "id_ed25519")
	os.WriteFile(outside, []byte("secret"), 0600)
	link := filepath.Join(outbox, "link.jpg")
	os.Symlink(outside, link)

	if rec := doReq(h, "/api/send", `{"recipient":"201001234567","media_path":"`+outside+`"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("file outside outbox: want 403, got %d", rec.Code)
	}
	if rec := doReq(h, "/api/send", `{"recipient":"201001234567","media_path":"`+link+`"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("symlink leaving outbox: want 403, got %d", rec.Code)
	}
	traversal := outbox + "/../" + filepath.Base(filepath.Dir(outside))
	if rec := doReq(h, "/api/send", `{"recipient":"201001234567","media_path":"`+traversal+`"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("../ path: want 403, got %d", rec.Code)
	}
	if len(*sent) != 0 {
		t.Fatalf("blocked files were sent: %v", *sent)
	}
	if rec := doReq(h, "/api/send", `{"recipient":"201001234567","media_path":"`+inside+`"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("file inside outbox: want 200, got %d", rec.Code)
	}
}

func TestBadRecipientRejected(t *testing.T) {
	h, _, sent := newTestAPI(t)
	for _, r := range []string{"", "123", "abc", "1234567890123456"} {
		if rec := doReq(h, "/api/send", `{"recipient":"`+r+`","message":"hi"}`, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("recipient %q: want 400, got %d", r, rec.Code)
		}
	}
	if len(*sent) != 0 {
		t.Fatal("bad recipient was sent to")
	}
}

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"../../escaped.txt":                  "escaped.txt",
		"../../Library/LaunchAgents/x.plist": "x.plist",
		`..\..\win.txt`:                      "win.txt",
		".zshrc":                             "zshrc",
		"report.pdf":                         "report.pdf",
		"bad\x00name\n.txt":                  "badname.txt",
	}
	for in, want := range cases {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "..", ".", "../", "/"} {
		if got := safeFileName(in); got == "" || strings.ContainsAny(got, `/\`) || strings.HasPrefix(got, ".") {
			t.Errorf("safeFileName(%q) = %q is unsafe", in, got)
		}
	}
	if got := safeFileName(strings.Repeat("ج", 400) + ".pdf"); len([]rune(got)) > 150 || !strings.HasSuffix(got, ".pdf") {
		t.Errorf("long name not shortened safely: %d runes", len([]rune(got)))
	}
}

func TestDownloadPathStaysInChatFolder(t *testing.T) {
	base := filepath.Join(t.TempDir(), "store", safeChatDirName("../../x@s.whatsapp.net"))
	if strings.Contains(filepath.Base(base), "..") && strings.HasPrefix(filepath.Base(base), ".") {
		t.Fatalf("chat dir name not cleaned: %s", base)
	}
	for _, name := range []string{"../../escaped.txt", "a/../../b", ".."} {
		p, err := joinInside(base, safeFileName(name))
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if filepath.Dir(p) != base {
			t.Fatalf("%q resolved outside chat folder: %s", name, p)
		}
	}
	if _, err := joinInside(base, "../x"); err == nil {
		t.Fatal("joinInside allowed ../x")
	}
}

func TestTokenFileIsPrivateAndStable(t *testing.T) {
	dir := t.TempDir()
	tok1, err := loadOrCreateToken(dir)
	if err != nil || len(tok1) != 64 {
		t.Fatalf("token: %q %v", tok1, err)
	}
	info, _ := os.Stat(filepath.Join(dir, apiTokenFile))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode %v, want 0600", info.Mode().Perm())
	}
	tok2, _ := loadOrCreateToken(dir)
	if tok1 != tok2 {
		t.Fatal("token changed between runs")
	}
}

func TestPrivateDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	os.MkdirAll(dir, 0755)
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatalf("dir mode %v, want 0700", info.Mode().Perm())
	}
}
