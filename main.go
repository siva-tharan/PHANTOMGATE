
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"phantomgate/internal/analyzer"
	"phantomgate/internal/deception"
	"phantomgate/internal/logger"
	"phantomgate/internal/terminal"
)

const sessionDuration = 30 * time.Minute

type App struct {
	log       *logger.Logger
	templates *template.Template

	adminUser     string
	adminPassword string
	secureCookie  bool

	sessionMu sync.Mutex
	sessions  map[string]time.Time
}

type InputRequest struct {
	Input string `json:"input"`
}

type FileRequest struct {
	Name string `json:"name"`
}

type AdminLoginData struct {
	CSRFToken string
	Error     string
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func visitorIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *App) record(
	r *http.Request,
	eventType, input string,
	score int,
	severity, details string,
) {
	err := a.log.Record(logger.Event{
		Time:      time.Now().UTC(),
		Type:      eventType,
		Input:     input,
		Score:     score,
		Severity:  severity,
		Details:   details,
		VisitorIP: visitorIP(r),
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		log.Printf("event logging error: %v", err)
	}
}

func (a *App) setCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "pg_csrf",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   1800,
	})

	return token, nil
}

func (a *App) validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("pg_csrf")
	if err != nil {
		return false
	}

	if err := r.ParseForm(); err != nil {
		return false
	}

	formToken := r.FormValue("csrf_token")

	if formToken == "" || cookie.Value == "" {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(cookie.Value),
		[]byte(formToken),
	) == 1
}

func (a *App) clearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pg_csrf",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (a *App) createSession() (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()

	now := time.Now()

	for existing, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, existing)
		}
	}

	a.sessions[token] = now.Add(sessionDuration)

	return token, nil
}

func (a *App) validSession(r *http.Request) bool {
	cookie, err := r.Cookie("pg_session")
	if err != nil {
		return false
	}

	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()

	expiry, exists := a.sessions[cookie.Value]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		delete(a.sessions, cookie.Value)
		return false
	}

	return true
}

func (a *App) destroySession(r *http.Request) {
	cookie, err := r.Cookie("pg_session")
	if err != nil {
		return
	}

	a.sessionMu.Lock()
	delete(a.sessions, cookie.Value)
	a.sessionMu.Unlock()
}

func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.validSession(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Administrator authentication required",
				})
				return
			}

			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next(w, r)
	}
}

// Public HTML page renderer.
func (a *App) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		if err := a.templates.ExecuteTemplate(w, name, nil); err != nil {
			log.Printf("template error (%s): %v", name, err)
			http.Error(w, "Page unavailable", http.StatusInternalServerError)
		}
	}
}

// Admin login page.
func (a *App) adminLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.validSession(r) {
		http.Redirect(w, r, "/investigation", http.StatusSeeOther)
		return
	}

	w.Header().Set("Cache-Control", "no-store")

	token, err := a.setCSRFCookie(w)
	if err != nil {
		http.Error(w, "Unable to initialize login", http.StatusInternalServerError)
		return
	}

	err = a.templates.ExecuteTemplate(w, "admin_login.html", AdminLoginData{
		CSRFToken: token,
	})

	if err != nil {
		log.Printf("admin login template error: %v", err)
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
	}
}

// Verify administrator credentials.
func (a *App) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	if !a.validCSRF(r) {
		http.Error(w, "Invalid login request. Refresh the page.", http.StatusForbidden)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	userOK := subtle.ConstantTimeCompare(
		[]byte(username),
		[]byte(a.adminUser),
	) == 1

	passwordOK := subtle.ConstantTimeCompare(
		[]byte(password),
		[]byte(a.adminPassword),
	) == 1

	if !userOK || !passwordOK {
		token, err := a.setCSRFCookie(w)
		if err != nil {
			http.Error(w, "Login unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)

		_ = a.templates.ExecuteTemplate(w, "admin_login.html", AdminLoginData{
			CSRFToken: token,
			Error:     "Invalid administrator credentials.",
		})
		return
	}

	session, err := a.createSession()
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "pg_session",
		Value:    session,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionDuration),
		MaxAge:   int(sessionDuration.Seconds()),
	})

	a.clearCSRFCookie(w)

	http.Redirect(w, r, "/investigation", http.StatusSeeOther)
}

// Administrator logout.
func (a *App) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !a.validCSRF(r) {
		http.Error(w, "Invalid logout request", http.StatusForbidden)
		return
	}

	a.destroySession(r)

	http.SetCookie(w, &http.Cookie{
		Name:     "pg_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	a.clearCSRFCookie(w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Simulated terminal API. No real OS commands are executed.
func (a *App) command(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req InputRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	req.Input = strings.TrimSpace(req.Input)

	if len(req.Input) == 0 || len(req.Input) > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Input must be 1-120 characters"})
		return
	}

	score, severity, details := analyzer.Analyze(req.Input)
	output := terminal.Run(req.Input)

	a.record(r, "TERMINAL", req.Input, score, severity, details)

	writeJSON(w, http.StatusOK, map[string]any{
		"output":   output,
		"score":    score,
		"severity": severity,
		"details":  details,
	})
}

// Visitor decoy login. Only username is recorded.
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req InputRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	username := strings.TrimSpace(req.Input)

	if len(username) == 0 || len(username) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username must be 1-80 characters"})
		return
	}

	a.record(
		r,
		"DECOY_LOGIN",
		username,
		40,
		"HIGH",
		"Decoy login interaction. No password was requested or stored.",
	)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "SIMULATED LOGIN FAILED: Activity recorded.",
	})
}

func (a *App) files(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, deception.Files())
}

func (a *App) readFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req FileRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	fileName := filepath.Base(req.Name)

	content, ok := deception.Read(fileName)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "File not found"})
		return
	}

	score, severity, details := analyzer.Analyze("cat " + fileName)

	a.record(r, "DECOY_FILE", fileName, score, severity, details)

	writeJSON(w, http.StatusOK, map[string]string{"content": content})
}

func (a *App) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, a.log.List())
}

func main() {
	adminUser := os.Getenv("PHANTOMGATE_ADMIN_USER")
	adminPassword := os.Getenv("PHANTOMGATE_ADMIN_PASSWORD")

	if adminUser == "" || adminPassword == "" {
		log.Fatal("Set PHANTOMGATE_ADMIN_USER and PHANTOMGATE_ADMIN_PASSWORD before starting.")
	}

	if len(adminUser) > 80 || len(adminPassword) < 16 || len(adminPassword) > 128 {
		log.Fatal("Admin username must be at most 80 characters; password must be 16-128 characters.")
	}

	secureCookie := strings.EqualFold(
		os.Getenv("PHANTOMGATE_SECURE_COOKIE"),
		"true",
	)

	eventLog, err := logger.New("data/events.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	defer eventLog.Close()

	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	app := &App{
		log:           eventLog,
		templates:     tmpl,
		adminUser:     adminUser,
		adminPassword: adminPassword,
		secureCookie:  secureCookie,
		sessions:      make(map[string]time.Time),
	}

	mux := http.NewServeMux()

	mux.Handle(
		"/static/",
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))),
	)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/terminal", http.StatusSeeOther)
	})

	// Public visitor pages.
	mux.HandleFunc("/terminal", app.page("terminal.html"))
	mux.HandleFunc("/explorer", app.page("explorer.html"))
	mux.HandleFunc("/trap", app.page("trap.html"))

	// Administrator authentication.
	mux.HandleFunc("/login", app.adminLoginPage)
	mux.HandleFunc("/admin/login", app.adminLogin)
	mux.HandleFunc("/admin/logout", app.adminLogout)

	// Protected administrator pages and APIs.
	mux.HandleFunc(
		"/investigation",
		app.requireAdmin(app.page("investigation.html")),
	)

	mux.HandleFunc("/api/events", app.requireAdmin(app.events))

	// Public simulation APIs.
	mux.HandleFunc("/api/command", app.command)
	mux.HandleFunc("/api/login", app.login)
	mux.HandleFunc("/api/files", app.files)
	mux.HandleFunc("/api/file/read", app.readFile)

	log.Println("PHANTOMGATE running at http://127.0.0.1:8080")

	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}
