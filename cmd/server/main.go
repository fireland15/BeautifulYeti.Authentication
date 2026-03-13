package main

import (
	"beautifulyeti/authentication/internal/auth"
	"beautifulyeti/authentication/internal/config"
	"beautifulyeti/authentication/internal/handlers"
	"beautifulyeti/authentication/internal/utils"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: by-auth [serve|healthcheck]")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "serve":
		startServer()
	case "healthcheck":
		checkHealth()
	default:
		fmt.Println("Unknown command:", cmd)
		fmt.Println("Usage: by-auth [serve|healthcheck]")
		os.Exit(1)
	}
}

func startServer() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx := context.Background()

	cfg, err := config.New()
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	redisClient := auth.NewRedisClient(cfg.RedisAddress(), cfg.RedisPassword())
	encryptionService := auth.NewEncryptionService(cfg.EncryptionKey())
	tokenCache := auth.NewTokenCache(redisClient, encryptionService)
	authSvc, err := auth.New(ctx, cfg, tokenCache)
	if err != nil {
		slog.Error("failed to initialize auth service", "err", err)
		os.Exit(1)
	}

	login := &handlers.LoginHandler{Auth: authSvc}
	callback := &handlers.CallbackHandler{Auth: authSvc}
	apiKeys := auth.ParseApiKeys(cfg)
	accessToken := handlers.NewAccessTokenHandler(redisClient, encryptionService, apiKeys, tokenCache, authSvc.OAuth2Config)
	logoutHandler := handlers.NewLogoutHandler(cfg, tokenCache)
	healthzHandler := handlers.NewHealthzHandler(redisClient)

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	mux.Handle("/oidc-callback", callback)
	mux.Handle("/access-token", accessToken)
	mux.Handle("/logout", logoutHandler)
	mux.Handle("/healthz", healthzHandler)

	handler := loggingMiddleware(mux)

	server := &http.Server{
		Addr:         cfg.ServerAddress(),
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	go func() {
		slog.Info("server starting", "addr", cfg.ServerAddress())

		if cfg.UseDevCerts() {
			slog.Info("using dev self-signed certificates")
			certFile := "cert.pem"
			keyFile := "key.pem"
			if err := utils.GenerateSelfSignedCert(certFile, keyFile); err != nil {
				slog.Error("failed to generate dev certs", "err", err)
				os.Exit(1)
			}

			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("server failed to start", "err", err)
				os.Exit(1)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server failed to start", "err", err)
				os.Exit(1)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	slog.Info("server shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "err", err)
		os.Exit(1)
	}

	slog.Info("server exited properly")
}

// loggingMiddleware logs all incoming HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

func checkHealth() {
	url := flag.String("url", "http://localhost:8443/healthz", "host to check")
	flag.Parse()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(*url)
	if err != nil {
		fmt.Println("Health check failed:", err)
		os.Exit(1)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("closing body reader", "err", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Health check failed: status", resp.Status)
		os.Exit(1)
	}
	fmt.Println("Health check passed")
}
