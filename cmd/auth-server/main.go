// auth-server is the long-running HTTP service: magic-link or password
// authentication, session-cookie minting, and identity verification.
//
// Lifecycle:
//   - Load + validate config (fails early on misconfiguration).
//   - Open SQLite store, run migrations, seed the domain allowlist
//     from AUTH_ALLOWED_DOMAINS.
//   - Start a background sweeper that GCs expired login/session state.
//   - Listen on AUTH_ADDR (default 127.0.0.1:9000). Caddy sits in
//     front and terminates TLS.
//   - On SIGINT/SIGTERM, drain in-flight requests and close the DB.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elcanotek/auth/internal/backchannel"
	"github.com/elcanotek/auth/internal/branding"
	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/email"
	"github.com/elcanotek/auth/internal/httpapi"
	"github.com/elcanotek/auth/internal/provisioning"
	"github.com/elcanotek/auth/internal/store"
)

func main() {
	var envFile string
	var checkOnly bool
	flag.StringVar(&envFile, "env", ".env.local", "path to .env file")
	flag.BoolVar(&checkOnly, "check-config", false, "load and validate the configuration and client branding, then exit (used by update.sh before a swap)")
	flag.Parse()

	cfg, err := config.Load(envFile)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	// Client branding comes from the same bundle Fleet consumes. A configured
	// but broken bundle is a config error: a client's auth host must not
	// silently ship the default look because of a typo.
	brand, err := branding.Load(cfg.ClientConfigDir)
	if err != nil {
		log.Fatalf("client branding: %v", err)
	}
	cfg.Brand = brand
	if brand != nil {
		log.Printf("client branding from %s (wordmark=%q logo=%v palette=%v)",
			brand.Dir, brand.AppName, len(brand.Logo) > 0, brand.CSS != "")
	}
	if cfg.LoginMode == "magic" && cfg.EmailDriver == "stdout" && cfg.CookieSecure {
		// Every sign-in link goes to the journal, where anyone who can read
		// it can sign in as the recipient. Loud, because the default is
		// this and a production box must not run on it.
		log.Printf("WARNING: AUTH_EMAIL_DRIVER=stdout on a secure magic-link deployment prints live sign-in links to the journal; set sendgrid or smtp")
	}
	if checkOnly {
		// update.sh runs this as the service user before swapping binaries,
		// while the current build is still serving. The live database is
		// opened read-only, never migrated: the start-time checks that
		// depend on its state run against it as it is.
		if ro, err := store.OpenReadOnly(cfg.DataDir); err == nil {
			if err := mfaKeyStartCheck(cfg, ro); err != nil {
				log.Fatalf("%v", err)
			}
			_ = ro.Close()
		} else if !os.IsNotExist(err) {
			log.Fatalf("open store read-only: %v", err)
		}
		log.Printf("configuration OK (hostname=%s, login_mode=%s, branding=%v)", cfg.Hostname, cfg.LoginMode, brand != nil)
		return
	}
	// Owner-only: the database holds password hashes, sealed authenticator
	// secrets and every email address.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}
	// MkdirAll leaves an existing directory's mode alone; narrow it too
	// (best effort: a directory owned by someone else cannot be changed).
	_ = os.Chmod(cfg.DataDir, 0o700)
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	if err := mfaKeyStartCheck(cfg, st); err != nil {
		log.Fatalf("%v", err)
	}
	defer func() { _ = st.Close() }()

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
	logoutDeliverer := backchannel.New(st, cfg.SigningKey, cfg.IssuerURL, &http.Client{Timeout: 10 * time.Second})
	accessDeliverer := provisioning.New(st, cfg.SigningKey, cfg.IssuerURL, &http.Client{Timeout: 10 * time.Second})

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
				now := time.Now().Unix()
				n, err := st.SweepExpired(ctx, now, 24*time.Hour)
				if err != nil {
					log.Printf("sweep: %v", err)
					continue
				}
				passwordN, err := st.SweepPasswordState(ctx, now, 24*time.Hour, cfg.AuditRetention)
				if err != nil {
					log.Printf("password state sweep: %v", err)
					continue
				}
				if n > 0 {
					log.Printf("sweep: deleted %d expired magic_links", n)
				}
				if passwordN > 0 {
					log.Printf("sweep: deleted %d expired password-state rows", passwordN)
				}
			}
		}
	}()

	// Back-channel logout exists only for password-mode applications; magic
	// mode has no registered clients, so skip the 2-second poll entirely.
	if cfg.LoginMode == "password" {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				if err := logoutDeliverer.RunOnce(ctx, time.Now()); err != nil && ctx.Err() == nil {
					log.Printf("back-channel logout: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				if err := accessDeliverer.RunOnce(ctx, time.Now()); err != nil && ctx.Err() == nil {
					log.Printf("application access provisioning: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}

	go func() {
		log.Printf("auth-server listening on %s (hostname=%s, login_mode=%s, cookie_domain=%q)",
			cfg.Addr, cfg.Hostname, cfg.LoginMode, cfg.CookieDomain)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown: draining in-flight requests")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// Shutdown returns once in-flight HTTP handlers finish, but each /magic
	// handler dispatches its email in a detached goroutine that outlives the
	// response. Drain those so a SIGTERM mid-send doesn't silently drop a
	// user's magic link. Bounded by the SAME shutCtx — HTTP drain + send
	// drain share one 15s total budget (the SIGTERM→SIGKILL window), not 15s
	// each; in practice the /magic handler returns instantly so the sends get
	// almost all of it.
	srv.WaitSends(shutCtx)
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

// mfaKeyStartCheck refuses to serve a password-mode database that needs
// AUTH_MFA_KEY without it: enrolled factors could not be verified, and
// accounts a policy requires to enroll could not. That is a misconfiguration,
// not a downgrade, and running would sign people out into a flow that
// cannot complete (an administrators policy would lock the console).
func mfaKeyStartCheck(cfg *config.Config, st *store.Store) error {
	if cfg.LoginMode != "password" || cfg.MFAKeyring != nil {
		return nil
	}
	reason, err := st.MFAKeyRequiredReason(context.Background())
	if err != nil {
		return fmt.Errorf("mfa: %w", err)
	}
	if reason != "" {
		return fmt.Errorf("AUTH_MFA_KEY is unset but %s; restore the key from the .env.local backup (or reset the factors and relax the policy with the CLI) before starting", reason)
	}
	log.Printf("2FA unavailable: AUTH_MFA_KEY is not set (generate one with `auth mfa keygen`)")
	return nil
}
