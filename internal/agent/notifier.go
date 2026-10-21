package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

// notifier decides where an alert goes. Agents connected to a dashboard hand
// alerts to it (for fleet-wide dedupe, silences and history) and deliver them
// directly only when the dashboard is unreachable. Other agents always deliver
// directly, through a bounded queue that drops (and counts) on overflow.
type notifier struct {
	sender *alert.Sender
	events *ring
	log    *slog.Logger // failures always; deliveries and routing at debug

	// route hands an alert to the dashboard; it returns false when the
	// dashboard is unreachable. nil for agents without a dashboard.
	route func(a Alert, hooks []*alert.Hook) bool
	// silenced reports whether a rule is silenced by the dashboard; used
	// when falling back to direct delivery, so silences still hold.
	silenced func(rule string) bool

	routed        atomic.Uint64 // handed to the dashboard
	fallback      atomic.Uint64 // delivered directly because the dashboard was unreachable
	silencedCount atomic.Uint64
	lastDropEvent atomic.Int64 // unix nanos
}

func newNotifier(queueSize, retries int, events *ring, log *slog.Logger) *notifier {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	n := &notifier{sender: alert.NewSender(queueSize, retries, "grepalert-agent/"+Version), events: events, log: log}
	n.sender.OnResult = func(a alert.Alert, r alert.Result) {
		took := r.Took.Round(time.Millisecond)
		if r.Err != nil {
			n.log.Warn("webhook delivery failed", "rule", a.Rule, "webhook", r.Hook, "attempts", r.Attempts,
				"took", took, "err", r.Err)
			n.events.add(Event{Time: time.Now(), Type: "webhook_error", Rule: a.Rule,
				Message: fmt.Sprintf("webhook %q: %v", r.Hook, r.Err)})
			return
		}
		n.log.Debug("webhook delivered", "rule", a.Rule, "webhook", r.Hook, "status", r.Status,
			"attempts", r.Attempts, "took", took)
	}
	return n
}

func (n *notifier) start(ctx context.Context, workers int) { n.sender.Start(ctx, workers) }
func (n *notifier) wait()                                  { n.sender.Wait() }

func hooksOf(r *rules.CompiledRule) []*alert.Hook {
	hooks := make([]*alert.Hook, len(r.Hooks))
	for i, w := range r.Hooks {
		hooks[i] = alert.FromRule(w)
	}
	return hooks
}

func (n *notifier) enqueue(a Alert, r *rules.CompiledRule) {
	hooks := hooksOf(r)
	if n.route != nil {
		if n.route(a, hooks) {
			n.routed.Add(1)
			n.log.Debug("alert handed to the dashboard, which sends it", "rule", a.Rule)
			return
		}
		n.fallbackDeliver(a, hooks)
		return
	}
	a.Via = "agent"
	n.direct(a, hooks)
}

// fallbackDeliver sends an alert the dashboard could not take, unless the
// dashboard had silenced its rule.
func (n *notifier) fallbackDeliver(a Alert, hooks []*alert.Hook) {
	if n.silenced != nil && n.silenced(a.Rule) {
		n.silencedCount.Add(1)
		n.log.Debug("alert not sent: the dashboard is unreachable and the rule is silenced", "rule", a.Rule)
		return
	}
	n.log.Debug("dashboard unreachable, the agent sends the alert itself", "rule", a.Rule)
	n.fallback.Add(1)
	a.Via = "agent"
	a.Text += " [sent by the agent: dashboard unreachable]"
	n.direct(a, hooks)
}

func (n *notifier) direct(a Alert, hooks []*alert.Hook) {
	for _, h := range hooks {
		if n.sender.Enqueue(a, h) {
			continue
		}
		total := n.sender.Dropped.Load()
		// One event per 10s at most, so a storm does not evict the event log.
		now := time.Now().UnixNano()
		if last := n.lastDropEvent.Load(); now-last >= int64(10*time.Second) && n.lastDropEvent.CompareAndSwap(last, now) {
			n.log.Warn("webhook queue full: alerts are being dropped", "rule", a.Rule, "dropped_total", total)
			n.events.add(Event{Time: time.Now(), Type: "webhook_error", Rule: a.Rule,
				Message: fmt.Sprintf("webhook queue full: alerts are being dropped (%d dropped so far)", total)})
		}
	}
}
