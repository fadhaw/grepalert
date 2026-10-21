package alert

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sender delivers alerts through a bounded queue drained by a fixed worker
// pool. When webhooks are slow or down the queue fills and new alerts are
// dropped (and counted) instead of piling up in memory.
type Sender struct {
	client    *http.Client
	queue     chan job
	retries   int
	userAgent string
	// OnResult, if set, is called after each delivery, successful or not.
	OnResult func(a Alert, r Result)

	Sent    atomic.Uint64
	Failed  atomic.Uint64
	Dropped atomic.Uint64

	wg sync.WaitGroup
}

type job struct {
	alert Alert
	hook  *Hook
}

// Result is the outcome of delivering one alert to one webhook.
type Result struct {
	Hook     string        // the webhook's name
	Err      error         // nil when it was delivered
	Status   int           // the last HTTP status received; 0 if none
	Attempts int           // requests made, retries included
	Took     time.Duration // from the first attempt to the outcome, waits included
}

// ShutdownGrace is how long deliveries may continue after stop is requested.
const ShutdownGrace = 5 * time.Second

func NewSender(queueSize, retries int, userAgent string) *Sender {
	return &Sender{
		client: &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}},
		queue:     make(chan job, queueSize),
		retries:   retries,
		userAgent: userAgent,
	}
}

// Start runs workers until ctx is done, then delivers what is queued within
// ShutdownGrace. Requests in flight are not cut off when ctx ends.
func (s *Sender) Start(ctx context.Context, workers int) {
	dctx, dcancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		time.AfterFunc(ShutdownGrace, dcancel)
	}()
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					s.flush(dctx)
					return
				case j := <-s.queue:
					s.deliver(dctx, j)
				}
			}
		}()
	}
}

func (s *Sender) Wait() { s.wg.Wait() }

// Queued is the number of deliveries waiting.
func (s *Sender) Queued() int { return len(s.queue) }

func (s *Sender) flush(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case j := <-s.queue:
			s.deliver(ctx, j)
		default:
			return
		}
	}
}

// Enqueue queues a for delivery to h. It returns false (and counts a drop)
// when the queue is full.
func (s *Sender) Enqueue(a Alert, h *Hook) bool {
	select {
	case s.queue <- job{alert: a, hook: h}:
		return true
	default:
		s.Dropped.Add(1)
		return false
	}
}

func (s *Sender) deliver(ctx context.Context, j job) {
	start := time.Now()
	res := Result{Hook: j.hook.Name}
	body, ctype, err := Render(j.alert, j.hook)
	if err == nil {
		backoff := time.Second
		for attempt := 0; ; attempt++ {
			res.Attempts++
			res.Status, err = s.send(ctx, j.hook, body, ctype)
			if err == nil || attempt >= s.retries || ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	} else {
		err = fmt.Errorf("render: %w", err)
	}
	if err == nil {
		s.Sent.Add(1)
	} else {
		s.Failed.Add(1)
	}
	if s.OnResult != nil {
		res.Err, res.Took = err, time.Since(start)
		s.OnResult(j.alert, res)
	}
}

// send makes one request; it returns the HTTP status (0 when there was no
// response) and an error for anything but a 2xx.
func (s *Sender) send(ctx context.Context, h *Hook, body []byte, ctype string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, h.Method, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", s.userAgent)
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused, never more.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return resp.StatusCode, nil
}
