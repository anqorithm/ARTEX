package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestRevokeSessions(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	stamp := time.Now().UnixNano()
	s := &Server{
		m:              m,
		jwtKey:         []byte("test-key-for-operator-session-revocation"),
		loginLimit:     newLoginLimiter(time.Now),
		authHashKey:    fmt.Sprintf("test.revoke_hash.%d", stamp),
		authVersionKey: fmt.Sprintf("test.revoke_version.%d", stamp),
	}
	defer func() {
		if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1 OR key=$2`, s.authHashKey, s.authVersionKey); err != nil {
			t.Error(err)
		}
	}()
	const password = "legacy-admin-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// A deployment set up before password versions were introduced has a hash
	// but no version row.
	if err := m.pg.SetSetting(s.authHashKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	s.loadPasswordVersion()
	handler := s.Handler()
	login := func() string {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/login",
			strings.NewReader(`{"username":"ARTEX","password":"`+password+`"}`)))
		var data struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); w.Code != http.StatusOK || err != nil || data.Token == "" {
			t.Fatalf("login status=%d body=%s err=%v", w.Code, w.Body.String(), err)
		}
		return data.Token
	}
	revoke := func(token, password, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/revoke-sessions",
			strings.NewReader(`{"password":"`+password+`"}`))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.RemoteAddr = ip
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	expectStatus := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want {
			t.Fatalf("revoke status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
	}
	first := login()
	second, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        "second-session",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if !s.sessionOK(second) {
		t.Fatal("legacy token was rejected before revocation")
	}
	const operatorIP = "192.0.2.10:1234"
	const otherIP = "192.0.2.11:1234"
	expectStatus(revoke("", password, operatorIP), http.StatusUnauthorized)
	for range loginMaxAttempts {
		expectStatus(revoke(first, "wrong", otherIP), http.StatusForbidden)
	}
	blocked := revoke(first, password, otherIP)
	expectStatus(blocked, http.StatusTooManyRequests)
	if blocked.Header().Get("Retry-After") == "" || !s.sessionOK(first) {
		t.Fatal("rate-limited confirmation did not preserve the session and retry delay")
	}

	// Two concurrent requests using the same session may only revoke once.
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { results <- revoke(first, password, operatorIP) }()
	}
	statuses := map[int]int{}
	for range 2 {
		statuses[(<-results).Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("concurrent revoke statuses=%v", statuses)
	}
	if s.pwdVersion.Load() != 1 || s.sessionOK(first) || s.sessionOK(second) {
		t.Fatal("revocation must advance the legacy version once and reject earlier sessions")
	}

	restarted := &Server{m: m, jwtKey: s.jwtKey, authVersionKey: s.authVersionKey}
	restarted.loadPasswordVersion()
	if restarted.sessionOK(first) {
		t.Fatal("revoked session worked after reloading the stored version")
	}
	current := login()
	if !restarted.sessionOK(current) {
		t.Fatal("fresh login with the original password did not work after revocation")
	}
	if err := m.pg.SetSetting(s.authVersionKey, "not-a-number"); err != nil {
		t.Fatal(err)
	}
	expectStatus(revoke(current, password, operatorIP), http.StatusServiceUnavailable)
	if !s.sessionOK(current) {
		t.Fatal("failed revocation invalidated a session before the version was saved")
	}
}

func TestLoginRejectsVersionChangeDuringPasswordCheck(t *testing.T) {
	s := &Server{loginLimit: newLoginLimiter(time.Now)}
	s.applyPasswordVersion(1)
	hash, err := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"username":"ARTEX","password":"current-password"}`))
	s.login(w, r, func(string) (string, bool, error) {
		s.applyPasswordVersion(2)
		return string(hash), true, nil
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("login status=%d want=%d body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
}
