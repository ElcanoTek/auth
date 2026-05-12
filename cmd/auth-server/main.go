// auth-server is the long-running HTTP service: magic-link issuance,
// session-cookie minting, and Caddy forward_auth verification.
//
// Lifecycle:
//   - Load + validate config (fails early on misconfiguration).
//   - Open SQLite store, run migrations, seed the domain allowlist
//     from AUTH_ALLOWED_DOMAINS.
//   - Start a background sweeper that GCs expired magic_links.
//   - Listen on AUTH_ADDR (default 127.0.0.1:9000). Caddy sits in
//     front and terminates TLS.
//   - On SIGINT/SIGTERM, drain in-flight requests and close the DB.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/email"
	"github.com/elcanotek/auth/internal/httpapi"
	"github.com/elcanotek/auth/internal/store"
)

func main() {
	var envFile string
	flag.StringVar(&envFile, "env", ".env.local", "path to .env file")
	flag.Parse()

	cfg, err := config.Load(envFile)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Seed the domain allowlist from env. This is additive — runtime
	// `auth domain add` entries are kept. Env changes that REMOVE a
	// domain need to be paired with `auth domain del`; we don't sync
	// deletions both ways because the env var is meant as a one-shot
	// bootstrap seed, not the source of truth.
	if len(cfg.AllowedDomains) > 0 {
		if err := st.SeedDomains(context.Background(), cfg.AllowedDomains); err != nil {
			log.Fatalf("seed domains: %v", err)
		}
	}

	sender := pickSender(cfg)
	srv := httpapi.New(cfg, st, sender)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Background sweeper. Keeps used + expired magic links from
	// accumulating forever. Cheap; runs every 10 min.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := st.SweepExpired(ctx, time.Now().Unix(), 24*time.Hour)
				if err != nil {
					log.Printf("sweep: %v", err)
					continue
				}
				if n > 0 {
					log.Printf("sweep: deleted %d expired magic_links", n)
				}
			}
		}
	}()

	go func() {
		log.Printf("auth-server listening on %s (hostname=%s, cookie_domain=%q)",
			cfg.Addr, cfg.Hostname, cfg.CookieDomain)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown: draining in-flight requests")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	log.Printf("shutdown: done")
}

// pickSender wires the email backend by config. Failing to set up
// resend/smtp at this point would surface as a 500 on the user's first
// /magic post, which is awful UX — config.Validate() runs the same
// shape check upstream so this function never sees an unknown driver.
func pickSender(cfg *config.Config) email.Sender {
	switch cfg.EmailDriver {
	case "sendgrid":
		return &email.SendGrid{APIKey: cfg.SendGridAPIKey, From: cfg.EmailFrom}
	case "smtp":
		return &email.SMTP{
			Host: cfg.SMTPHost,
			Port: cfg.SMTPPort,
			User: cfg.SMTPUser,
			Pass: cfg.SMTPPass,
			From: cfg.EmailFrom,
		}
	default:
		return email.Stdout{}
	}
}
