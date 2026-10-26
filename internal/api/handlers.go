package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dollysensor/internal/blocklist"
	"dollysensor/internal/rules"
	"dollysensor/internal/sensor"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.Status())
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.Overview())
}

func (s *Server) handleDestinations(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 200, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows := s.sensor.DestinationRows(limit)
	writeJSON(w, http.StatusOK, map[string]any{"destinations": rows, "count": len(rows)})
}

func (s *Server) handleDestination(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	detail, err := s.sensor.DestinationDetail(ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleIntelligence(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.Intelligence())
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 200, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	port := 0
	if rawPort := strings.TrimSpace(r.URL.Query().Get("port")); rawPort != "" {
		parsed, err := strconv.Atoi(rawPort)
		if err != nil || parsed < 1 || parsed > 65535 {
			writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
			return
		}
		port = parsed
	}
	filter := sensor.PacketFilter{
		Destination: r.URL.Query().Get("destination"),
		Source:      r.URL.Query().Get("source"),
		Port:        uint16(port),
		Protocol:    r.URL.Query().Get("protocol"),
		Direction:   r.URL.Query().Get("direction"),
		Query:       r.URL.Query().Get("q"),
		Limit:       limit,
	}
	packets := s.sensor.Observations(filter)
	writeJSON(w, http.StatusOK, map[string]any{"packets": packets, "count": len(packets)})
}

func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}
	obs, ok := s.sensor.Observation(id)
	if !ok {
		writeError(w, http.StatusNotFound, "packet not found in the bounded ring")
		return
	}
	writeJSON(w, http.StatusOK, obs)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 500, 2000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.sensor.Connections(limit))
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 200, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	severity := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))
	switch severity {
	case "", "info", "warning", "critical":
	default:
		writeError(w, http.StatusBadRequest, "severity must be info, warning, or critical")
		return
	}
	alerts := s.sensor.Alerts(limit, severity)
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts, "count": len(alerts)})
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	alert, ok := s.sensor.Alert(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.BlocklistInfo())
}

func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Entry) == "" {
		writeError(w, http.StatusBadRequest, "entry is required")
		return
	}
	if err := s.sensor.AddBlocklistEntry(body.Entry); err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "blocklist": s.sensor.BlocklistInfo()})
}

func (s *Server) handleRemoveBlocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.sensor.RemoveBlocklistEntry(body.Entry); err != nil {
		writeListError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "blocklist": s.sensor.BlocklistInfo()})
}

func (s *Server) handleReloadBlocklist(w http.ResponseWriter, r *http.Request) {
	warnings, err := s.sensor.ReloadBlocklist()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed; previous blocklist remains active: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warnings": warnings, "blocklist": s.sensor.BlocklistInfo()})
}

func writeListError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, blocklist.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, blocklist.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, blocklist.ErrInvalidEntry), errors.Is(err, blocklist.ErrProtected), errors.Is(err, blocklist.ErrDefaultRoute):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"manual": s.sensor.ManualTrust(),
		"global": s.sensor.TrustedSet().Strings(),
	})
}

func (s *Server) handleSetTrust(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Destination string `json:"destination"`
		Source      string `json:"source"`
		Trusted     *bool  `json:"trusted"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Trusted == nil {
		writeError(w, http.StatusBadRequest, "trusted is required")
		return
	}
	if err := s.sensor.SetTrust(body.Destination, body.Source, *body.Trusted); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manual": s.sensor.ManualTrust()})
}

func (s *Server) handleMitigations(w http.ResponseWriter, r *http.Request) {
	status := s.sensor.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"simulated": status.Simulated,
		"bgp":       status.BGP,
		"counts":    status.Mitigation,
		"active":    s.sensor.ActiveMitigations(),
		"history":   s.sensor.MitigationHistory(500),
	})
}

func (s *Server) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	action, err := s.sensor.WithdrawMitigation(id, body.Reason)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already") {
			status = http.StatusConflict
		}
		payload := map[string]any{"error": err.Error()}
		if action != nil {
			payload["action"] = action
		}
		writeJSON(w, status, payload)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": action})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.RuleData())
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var input rules.Rule
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rule, err := s.sensor.CreateRule(ctx, input)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rule created", "rule", rule.ID, "name", rule.Name, "mode", rule.Mode, "action", rule.Action.Type)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input rules.Rule
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rule, err := s.sensor.UpdateRule(ctx, id, input)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rule updated", "rule", rule.ID, "name", rule.Name, "enabled", rule.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleSetRuleEnabled(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rule, err := s.sensor.SetRuleEnabled(ctx, id, *body.Enabled)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rule enabled state changed", "rule", rule.ID, "name", rule.Name, "enabled", rule.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rule, err := s.sensor.DeleteRule(ctx, id)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rule deleted", "rule", rule.ID, "name", rule.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleReorderRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Order []string `json:"order"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	list, err := s.sensor.ReorderRules(ctx, body.Order)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rules reordered", "count", len(list))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": list})
}

func (s *Server) handleMoveRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Position *int `json:"position"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Position == nil {
		writeError(w, http.StatusBadRequest, "position is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	list, err := s.sensor.MoveRule(ctx, id, *body.Position)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	s.logger.Info("rule moved", "rule", id, "position", *body.Position)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": list})
}

func (s *Server) handlePreviewRule(w http.ResponseWriter, r *http.Request) {
	var input rules.Rule
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.sensor.PreviewRule(input)
	if err != nil {
		writeRuleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "preview": result})
}

func writeRuleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rules.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, rules.ErrCapacity):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, rules.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, rules.ErrDisabled):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.sensor.Settings())
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.sensor.SendTestAlert(ctx); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "test notification delivered"})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()

	allowed := map[string]bool{}
	if raw := r.URL.Query().Get("types"); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			allowed[strings.TrimSpace(value)] = true
		}
	}
	sub := s.sensor.Subscribe(256)
	defer s.sensor.Unsubscribe(sub)
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case event, ok := <-sub.C:
			if !ok {
				return
			}
			if len(allowed) > 0 && !allowed[event.Type] {
				continue
			}
			data, err := json.Marshal(event.Data)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func queryLimit(r *http.Request, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, errors.New("limit must be a positive integer")
	}
	if value > maximum {
		value = maximum
	}
	return value, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains trailing JSON data")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains trailing JSON data")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}
