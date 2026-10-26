// Package api serves the loopback dashboard, its JSON API, and the live SSE
// stream. It has no authentication by design and is intended to bind only to
// loopback (the shipped default).
package api

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dollysensor/internal/sensor"
)

//go:embed web/index.html web/app.css web/app.js web/views.js
var webFS embed.FS

// Server exposes a Sensor over HTTP.
type Server struct {
	sensor *sensor.Sensor
	logger *slog.Logger
	mux    *http.ServeMux
	once   sync.Once
}

// New constructs the HTTP handler. Routes are registered once.
func New(s *sensor.Sensor, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{sensor: s, logger: logger, mux: http.NewServeMux()}
	server.routes()
	return server
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/overview", s.handleOverview)
	s.mux.HandleFunc("GET /api/destinations", s.handleDestinations)
	s.mux.HandleFunc("GET /api/destinations/{ip}", s.handleDestination)
	s.mux.HandleFunc("GET /api/intelligence", s.handleIntelligence)
	s.mux.HandleFunc("GET /api/packets", s.handlePackets)
	s.mux.HandleFunc("GET /api/packets/{id}", s.handlePacket)
	s.mux.HandleFunc("GET /api/alerts", s.handleAlerts)
	s.mux.HandleFunc("GET /api/alerts/{id}", s.handleAlert)
	s.mux.HandleFunc("GET /api/blocklist", s.handleBlocklist)
	s.mux.HandleFunc("POST /api/blocklist", s.handleAddBlocklist)
	s.mux.HandleFunc("DELETE /api/blocklist", s.handleRemoveBlocklist)
	s.mux.HandleFunc("POST /api/blocklist/reload", s.handleReloadBlocklist)
	s.mux.HandleFunc("GET /api/trust", s.handleTrust)
	s.mux.HandleFunc("POST /api/trust", s.handleSetTrust)
	s.mux.HandleFunc("GET /api/mitigations", s.handleMitigations)
	s.mux.HandleFunc("POST /api/mitigations/{id}/withdraw", s.handleWithdraw)
	s.mux.HandleFunc("GET /api/rules", s.handleRules)
	s.mux.HandleFunc("POST /api/rules", s.handleCreateRule)
	s.mux.HandleFunc("POST /api/rules/preview", s.handlePreviewRule)
	s.mux.HandleFunc("POST /api/rules/packs", s.handleImportPack)
	s.mux.HandleFunc("POST /api/rules/packs/{name}/import", s.handleImportPackByName)
	s.mux.HandleFunc("PUT /api/rules/order", s.handleReorderRules)
	s.mux.HandleFunc("PUT /api/rules/{id}", s.handleUpdateRule)
	s.mux.HandleFunc("PATCH /api/rules/{id}/enabled", s.handleSetRuleEnabled)
	s.mux.HandleFunc("POST /api/rules/{id}/move", s.handleMoveRule)
	s.mux.HandleFunc("DELETE /api/rules/{id}", s.handleDeleteRule)
	s.mux.HandleFunc("GET /api/settings", s.handleSettings)
	s.mux.HandleFunc("POST /api/settings/test-webhook", s.handleTestWebhook)
	s.mux.HandleFunc("GET /api/detection", s.handleGetDetection)
	s.mux.HandleFunc("PUT /api/detection", s.handleUpdateDetection)
	s.mux.HandleFunc("GET /api/events", s.handleEvents)
	s.mux.HandleFunc("GET /assets/app.css", s.handleCSS)
	s.mux.HandleFunc("GET /assets/app.js", s.handleJS)
	s.mux.HandleFunc("GET /assets/views.js", s.handleViewsJS)
	s.mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

// Run starts the dashboard and blocks until ctx is cancelled or the listener
// fails.
func (s *Server) Run(ctx context.Context) error {
	addr := s.sensor.Config().Dashboard.Listen
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()
	s.logger.Info("dashboard listening", "address", listener.Addr().String())
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			_ = httpServer.Close()
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Dolly-Request") != "1" {
				writeError(w, http.StatusForbidden, "missing X-Dolly-Request header")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				if !sameOrigin(origin, r.Host) {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	origin = strings.TrimSpace(origin)
	host = strings.TrimSpace(host)
	if origin == "" {
		return true
	}
	if strings.HasPrefix(origin, "http://") {
		return strings.TrimPrefix(origin, "http://") == host
	}
	if strings.HasPrefix(origin, "https://") {
		return strings.TrimPrefix(origin, "https://") == host
	}
	return false
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard asset unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/app.css")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard asset unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func (s *Server) handleJS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/app.js")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard asset unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func (s *Server) handleViewsJS(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/views.js")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard asset unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.sensor.Version()})
}
