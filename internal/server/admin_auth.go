package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	adminSessionCookie   = "zentloop_admin"
	adminSessionLifetime = 12 * time.Hour
	maxAdminSessions     = 256
)

type adminSession struct {
	CreatedAt time.Time
	ExpiresAt time.Time
	CSRF      string
}

func randomAdminToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func adminSessionKey(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func (s *AdminServer) createAdminSession(now time.Time) (string, adminSession, error) {
	token, err := randomAdminToken(32)
	if err != nil {
		return "", adminSession{}, err
	}
	csrf, err := randomAdminToken(24)
	if err != nil {
		return "", adminSession{}, err
	}
	sess := adminSession{CreatedAt: now, ExpiresAt: now.Add(adminSessionLifetime), CSRF: csrf}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for key, existing := range s.adminSessions {
		if !existing.ExpiresAt.After(now) {
			delete(s.adminSessions, key)
		}
	}
	for len(s.adminSessions) >= maxAdminSessions {
		var oldestKey [32]byte
		var oldest time.Time
		for key, existing := range s.adminSessions {
			if oldest.IsZero() || existing.CreatedAt.Before(oldest) {
				oldestKey, oldest = key, existing.CreatedAt
			}
		}
		delete(s.adminSessions, oldestKey)
	}
	s.adminSessions[adminSessionKey(token)] = sess
	return token, sess, nil
}

func (s *AdminServer) adminSessionFromRequest(r *http.Request, now time.Time) (adminSession, bool) {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return adminSession{}, false
	}
	key := adminSessionKey(cookie.Value)
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	sess, ok := s.adminSessions[key]
	if !ok {
		return adminSession{}, false
	}
	if !sess.ExpiresAt.After(now) {
		delete(s.adminSessions, key)
		return adminSession{}, false
	}
	return sess, true
}

func (s *AdminServer) deleteAdminSession(r *http.Request) {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return
	}
	s.sessionMu.Lock()
	delete(s.adminSessions, adminSessionKey(cookie.Value))
	s.sessionMu.Unlock()
}

func adminRequestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(adminSessionLifetime.Seconds()),
		HttpOnly: true,
		Secure:   adminRequestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAdminSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   adminRequestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *AdminServer) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid login payload", http.StatusBadRequest)
		return
	}
	ip := remoteIP(r.RemoteAddr)
	userMismatch := subtleStringMismatch(body.Username, s.cfg.AdminUser)
	passwordMismatch := subtleStringMismatch(body.Password, s.cfg.AdminPassword)
	valid := !userMismatch && !passwordMismatch
	if !valid {
		delay := s.recordAdminAuthFailure(ip, time.Now())
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid credentials"})
		return
	}
	s.clearAdminAuthFailures(ip)
	token, sess, err := s.createAdminSession(time.Now())
	if err != nil {
		http.Error(w, "failed to create admin session", http.StatusInternalServerError)
		return
	}
	setAdminSessionCookie(w, r, token, sess.ExpiresAt)
	writeJSON(w, map[string]any{"ok": true, "user": s.cfg.AdminUser, "csrf": sess.CSRF, "expires_at": sess.ExpiresAt})
}

func (s *AdminServer) adminSessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := s.adminSessionFromRequest(r, time.Now())
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, map[string]any{"authenticated": true, "user": s.cfg.AdminUser, "csrf": sess.CSRF, "expires_at": sess.ExpiresAt})
}

func (s *AdminServer) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	sess, ok := s.adminSessionFromRequest(r, time.Now())
	if !ok {
		clearAdminSessionCookie(w, r)
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"ok": false})
		return
	}
	if subtleStringMismatch(r.Header.Get("X-ZentLoop-CSRF"), sess.CSRF) {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{"ok": false, "error": "csrf validation failed"})
		return
	}
	s.deleteAdminSession(r)
	clearAdminSessionCookie(w, r)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *AdminServer) adminLoginPage(web fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if _, ok := s.adminSessionFromRequest(r, time.Now()); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		data, err := fs.ReadFile(web, "login.html")
		if err != nil {
			http.Error(w, "login page unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}
}

func (s *AdminServer) adminSessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		sess, ok := s.adminSessionFromRequest(r, time.Now())
		if !ok && (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-ZentLoop-Client") == "top" {
			u, p, hasBasic := r.BasicAuth()
			userMismatch := subtleStringMismatch(u, s.cfg.AdminUser)
			passwordMismatch := subtleStringMismatch(p, s.cfg.AdminPassword)
			if hasBasic && !userMismatch && !passwordMismatch {
				s.clearAdminAuthFailures(remoteIP(r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}
		}
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") || headerHasToken(r.Header, "Connection", "upgrade") {
				writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			nextPath := r.URL.RequestURI()
			if nextPath == "" || nextPath == "/" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(nextPath), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if subtleStringMismatch(r.Header.Get("X-ZentLoop-CSRF"), sess.CSRF) {
				writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": "csrf validation failed"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
