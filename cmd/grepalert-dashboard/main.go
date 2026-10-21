// Command grepalert-dashboard serves the web UI for connecting grepalert
// agents, grouping them under shared rule sets and monitoring them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fadhaw/grepalert/internal/dashboard"
	"github.com/fadhaw/grepalert/internal/version"
)

func main() {
	configPath := flag.String("config", "dashboard.yaml", "path to dashboard config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("grepalert-dashboard", version.Version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := dashboard.LoadConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	store, err := dashboard.OpenStore(cfg.DataFile)
	if err != nil {
		log.Error("open data file", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version.Version, "listen", cfg.Listen)
	s := dashboard.New(cfg, store, log)
	if !s.AuthConfigured() {
		log.Warn("no sign-in configured (auth.password, auth.oidc or local users): anyone who can reach the dashboard is an admin")
	}
	defer s.Close()
	go s.RunReconciler(ctx)
	go s.RunFleet(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // a group sync may take a while
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		s.Shutdown() // release agents' held polls first
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Info("dashboard listening", "addr", cfg.Listen, "data_file", cfg.DataFile,
		"agents", len(store.Agents()), "groups", len(store.Groups()))
	if cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}
