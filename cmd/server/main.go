package main

import (
	"beautifulyeti/authentication/internal/auth"
	"beautifulyeti/authentication/internal/config"
	"beautifulyeti/authentication/internal/handlers"
	"beautifulyeti/authentication/internal/utils"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
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
	ctx := context.Background()

	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	redisClient := auth.NewRedisClient(cfg.RedisAddress(), cfg.RedisPassword())
	encryptionService := auth.NewEncryptionService(cfg.EncryptionKey())
	tokenCache := auth.NewTokenCache(redisClient, encryptionService)
	authSvc, err := auth.New(ctx, cfg, tokenCache)
	if err != nil {
		log.Fatal(err)
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

	// Create server with timeout settings
	server := &http.Server{
		Addr:         cfg.ServerAddress(),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Println("server started on", cfg.ServerAddress())

		if cfg.UseDevCerts() {
			log.Println("using dev-certs")
			certFile := "cert.pem"
			keyFile := "key.pem"
			if err := utils.GenerateSelfSignedCert(certFile, keyFile); err != nil {
				log.Fatal("failed to generate self-signed dev certs", err)
			}

			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatal("server failed to start:", err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal("server failed to start:", err)
			}
		}
	}()

	// Wait for the interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("shutting down server...")

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("server forced to shutdown:", err)
	}
	log.Println("server exited properly")
}
func checkHealth() {
	// Flags for optional host/port
	host := flag.String("host", "localhost", "host to check")
	port := flag.String("port", "8443", "port to check")
	insecure := flag.Bool("insecure", true, "skip TLS verification")
	flag.Parse()

	url := fmt.Sprintf("https://%s:%s/healthz", *host, *port)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	if *insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	resp, err := client.Get(url)
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
