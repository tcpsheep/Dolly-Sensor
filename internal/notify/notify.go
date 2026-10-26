// Package notify delivers critical alerts to a webhook without ever blocking
// packet ingestion. Delivery failures are recorded, not escalated into sensor
// failures, and webhook URLs are never logged.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Notification is the content of one webhook delivery.
type Notification struct {
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Type        string    `json:"type,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Source      string    `json:"source,omitempty"`
	Reason      string    `json:"reason"`
	Signals     []string  `json:"signals,omitempty"`
	Action      string    `json:"action,omitempty"`
	Simulated   bool      `json:"simulated,omitempty"`
	At          time.Time `json:"at"`
	Test        bool      `json:"test,omitempty"`
}

// Options configures delivery.
type Options struct {
	URL     string
	Format  string
	Timeout time.Duration
	Retries int
	Logger  *slog.Logger
}

// Stats is the visible delivery state.
type Stats struct {
	Configured  bool      `json:"configured"`
	Format      string    `json:"format"`
	Queue       int       `json:"queue"`
	Sent        uint64    `json:"sent"`
	Failed      uint64    `json:"failed"`
	Dropped     uint64    `json:"dropped"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
}

// Notifier owns a bounded delivery queue.
type Notifier struct {
	opts   Options
	client *http.Client
	queue  chan Notification
	logger *slog.Logger

	mu        sync.Mutex
	stats     Stats
	started   bool
	stop      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

// New creates a notifier. A notifier with no URL is a no-op that reports
// itself as unconfigured.
func New(opts Options) *Notifier {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	format := strings.ToLower(opts.Format)
	if format == "" {
		format = "discord"
	}
	n := &Notifier{
		opts:    opts,
		client:  &http.Client{Timeout: opts.Timeout},
		queue:   make(chan Notification, 128),
		logger:  opts.Logger,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	n.stats = Stats{Configured: opts.URL != "", Format: format}
	close(n.stopped)
	return n
}

// Start launches the background delivery worker.
func (n *Notifier) Start(ctx context.Context) {
	if n.opts.URL == "" {
		return
	}
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return
	}
	n.started = true
	n.stopped = make(chan struct{})
	n.mu.Unlock()
	go n.run(ctx)
}

// Enqueue submits a notification without blocking.
func (n *Notifier) Enqueue(value Notification) bool {
	if n.opts.URL == "" {
		return false
	}
	select {
	case n.queue <- value:
		return true
	default:
		n.mu.Lock()
		n.stats.Dropped++
		n.mu.Unlock()
		n.logger.Warn("webhook queue full; dropping notification", "type", value.Type, "destination", value.Destination)
		return false
	}
}

func (n *Notifier) run(ctx context.Context) {
	defer func() {
		n.mu.Lock()
		n.started = false
		n.stopped = make(chan struct{})
		close(n.stopped)
		n.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.stop:
			return
		case value := <-n.queue:
			if err := n.SendNow(ctx, value); err != nil {
				n.logger.Warn("webhook delivery failed", "type", value.Type, "error", n.sanitize(err))
			}
		}
	}
}

// SendNow delivers immediately. It is used for the dashboard's test button and
// by the background worker.
func (n *Notifier) SendNow(ctx context.Context, value Notification) error {
	if n.opts.URL == "" {
		return errors.New("webhook is not configured")
	}
	if value.At.IsZero() {
		value.At = time.Now()
	}
	body, err := n.encode(value)
	if err != nil {
		return err
	}
	attempts := n.opts.Retries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		n.mu.Lock()
		n.stats.LastAttempt = time.Now()
		n.mu.Unlock()
		err = n.post(ctx, body)
		if err == nil {
			n.mu.Lock()
			n.stats.Sent++
			n.stats.LastSuccess = time.Now()
			n.stats.LastError = ""
			n.mu.Unlock()
			return nil
		}
		lastErr = err
		n.mu.Lock()
		n.stats.LastError = n.sanitize(err)
		n.mu.Unlock()
		if attempt+1 < attempts {
			delay := time.Duration(attempt+1) * 500 * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	n.mu.Lock()
	n.stats.Failed++
	n.mu.Unlock()
	return lastErr
}

func (n *Notifier) post(ctx context.Context, body []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.opts.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "DollySensor/1.0")
	response, err := n.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 4096)
	responseBody, _ := io.ReadAll(limited)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := strings.TrimSpace(string(responseBody))
		if detail != "" {
			return fmt.Errorf("webhook returned HTTP %d: %s", response.StatusCode, detail)
		}
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (n *Notifier) encode(value Notification) ([]byte, error) {
	if strings.EqualFold(n.opts.Format, "generic") {
		return json.Marshal(value)
	}
	content := formatDiscord(value)
	if len(content) > 1950 {
		content = content[:1950] + "…"
	}
	return json.Marshal(map[string]any{
		"content":          content,
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
}

func formatDiscord(value Notification) string {
	severity := strings.ToUpper(value.Severity)
	if severity == "" {
		severity = "INFO"
	}
	title := value.Title
	if title == "" {
		title = "Dolly Sensor alert"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**[%s] %s**\n", severity, title)
	if value.Destination != "" {
		fmt.Fprintf(&b, "Destination: `%s`\n", value.Destination)
	}
	if value.Source != "" {
		fmt.Fprintf(&b, "Source: `%s`\n", value.Source)
	}
	if value.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", value.Reason)
	}
	if len(value.Signals) > 0 {
		b.WriteString("Evidence:\n")
		for _, signal := range value.Signals {
			fmt.Fprintf(&b, "• %s\n", signal)
		}
	}
	if value.Action != "" {
		if value.Simulated {
			fmt.Fprintf(&b, "Action (SIMULATED): %s\n", value.Action)
		} else {
			fmt.Fprintf(&b, "Action: %s\n", value.Action)
		}
	}
	fmt.Fprintf(&b, "Time: %s UTC", value.At.UTC().Format("2006-01-02 15:04:05"))
	return b.String()
}

func (n *Notifier) sanitize(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if n.opts.URL != "" {
		text = strings.ReplaceAll(text, n.opts.URL, "[webhook]")
	}
	return text
}

// Stats returns delivery state.
func (n *Notifier) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	stats := n.stats
	stats.Queue = len(n.queue)
	return stats
}

// Close stops the worker and waits briefly for it to finish. Queued alerts may
// be dropped; ingestion and mitigation cleanup take priority on shutdown.
func (n *Notifier) Close() {
	n.closeOnce.Do(func() {
		close(n.stop)
		n.mu.Lock()
		started := n.started
		stopped := n.stopped
		n.mu.Unlock()
		if started {
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
			}
		}
	})
}
