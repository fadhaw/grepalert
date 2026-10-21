// Command grepalert-agent tails log files and sends webhook alerts when lines
// match rules. Rules are hot-reloaded from disk or pushed via its HTTP API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/rules"
)

func main() {
	configPath := flag.String("config", "agent.yaml", "path to agent config")
	check := flag.String("check", "", "validate a rules file and exit")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("grepalert-agent", agent.Version)
		return
	}
	if *check != "" {
		raw, err := os.ReadFile(*check)
		if err == nil {
			var c *rules.Compiled
			if c, err = rules.Parse(raw); err == nil {
				fmt.Printf("OK: %d active rules, %d webhooks, hash %s\n", len(c.Rules), len(c.Webhooks), c.Hash)
				return
			}
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := agent.New(cfg, log)
	cfg = a.Config() // with defaults applied
	log.Info("starting", "name", cfg.Name, "version", agent.Version, "dashboard", cfg.Dashboard.URL, "listen", cfg.Listen)

	var srv *http.Server
	if cfg.Listen != "off" {
		if cfg.Token == "" && !loopbackOnly(cfg.Listen) {
			log.Warn("no token configured: anyone who can reach the agent API can change its rules", "listen", cfg.Listen)
		}
		srv = a.Server()
		go func() {
			var err error
			if cfg.TLSCert != "" {
				err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("API server", "err", err)
				stop()
			}
		}()
	}

	if err := a.Run(ctx); err != nil {
		log.Error("agent", "err", err)
		os.Exit(1)
	}
	if srv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}
	log.Info("stopped")
}

// loopbackOnly reports whether addr only accepts connections from this
// machine (127.0.0.1, ::1 or localhost).
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
