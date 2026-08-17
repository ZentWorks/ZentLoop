package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"zentloop/internal/config"
	"zentloop/internal/server"
	"zentloop/internal/store"
	"zentloop/internal/support"
	"zentloop/internal/tui"
)

const version = "0.2.21"

func main() {
	if filepath.Base(os.Args[0]) == "support" {
		dataDir := strings.TrimSpace(os.Getenv("ZENTLOOP_DATA_DIR"))
		if dataDir == "" {
			dataDir = "/data"
		}
		if err := support.RunCommand(os.Stdin, os.Stdout, dataDir, version, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "Support export failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "top":
			if err := tui.Run(os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		case "version", "--version", "-v":
			fmt.Println("ZentLoop " + version)
			return
		case "help", "--help", "-h":
			usage()
			return
		case "serve":
		}
	}
	if err := serve(); err != nil {
		log.Fatal(err)
	}
}

func serve() error {
	cfg := config.Load()
	generatedPassword := false
	if cfg.AdminPassword == "" {
		password, err := randomAdminPassword()
		if err != nil {
			return fmt.Errorf("generate admin password: %w", err)
		}
		cfg.AdminPassword = password
		generatedPassword = true
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if generatedPassword {
		log.Printf("ZentLoop generated administrator password: %s", cfg.AdminPassword)
		log.Printf("Set ZENTLOOP_ADMIN_PASSWORD to keep a stable administrator password across restarts")
	}
	st, err := store.NewWithRetention(cfg.DataDir, cfg.RetentionDays)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()
	trap := &http.Server{Addr: cfg.TrapAddr, Handler: server.NewTrap(cfg, st).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 32 << 10}
	admin := &http.Server{Addr: cfg.AdminAddr, Handler: server.NewAdmin(cfg, st).Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	var trapSSH *server.TrapSSH
	if cfg.SSHEnabled {
		trapSSH, err = server.NewTrapSSH(cfg, st)
		if err != nil {
			return fmt.Errorf("SSH trap: %w", err)
		}
	}
	var adminSSH *server.AdminSSH
	if cfg.AdminSSHEnabled {
		adminSSH, err = server.NewAdminSSH(cfg)
		if err != nil {
			if trapSSH != nil {
				_ = trapSSH.Close()
			}
			return fmt.Errorf("admin ssh: %w", err)
		}
	}

	errch := make(chan error, 4)
	go func() {
		log.Printf("ZentLoop %s trap listening on %s (domain or IP), proxy=%s", version, cfg.TrapAddr, cfg.ProxyMode)
		if e := trap.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errch <- e
		}
	}()
	go func() {
		log.Printf("ZentLoop admin listening on %s", cfg.AdminAddr)
		if e := admin.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errch <- e
		}
	}()
	if trapSSH != nil {
		go func() {
			log.Printf("ZentLoop SSH trap listening on %s (fully virtual shell; no OS exec/network/filesystem access)", trapSSH.Addr())
			if e := trapSSH.Serve(); e != nil {
				errch <- e
			}
		}()
	}
	if adminSSH != nil {
		go func() {
			log.Printf("ZentLoop admin SSH listening on %s as %s (public-key only, live top only)", adminSSH.Addr(), cfg.AdminSSHUser)
			if e := adminSSH.Serve(); e != nil {
				errch <- e
			}
		}()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
	case e := <-errch:
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = trap.Shutdown(ctx)
	_ = admin.Shutdown(ctx)
	if trapSSH != nil {
		_ = trapSSH.Close()
	}
	if adminSSH != nil {
		_ = adminSSH.Close()
	}
	return nil
}

func randomAdminPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func usage() {
	fmt.Printf(`ZentLoop %s

Usage:
  zentloop [serve]      Start trap + admin service
  zentloop top [flags]  Live terminal overview
  zentloop version      Print version

Top flags:
  -url URL               Admin URL (default http://127.0.0.1:9090)
  -user USER             Admin user
  -password PASSWORD     Admin password
  -interval 1s           Refresh interval
`, version)
}
