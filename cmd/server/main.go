package main

import (
	auth2 "beautifulyeti/authentication/internal/auth"
	"beautifulyeti/authentication/internal/config"
	handlers2 "beautifulyeti/authentication/internal/handlers"
	"beautifulyeti/authentication/internal/utils"
	"context"
	"log"
	"net/http"
)

func main() {
	ctx := context.Background()

	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	redisClient := auth2.NewRedisClient(cfg.RedisAddress(), cfg.RedisPassword())
	encryptionService := auth2.NewEncryptionService(cfg.EncryptionKey())
	tokenCache := auth2.NewTokenCache(redisClient, encryptionService)
	authSvc, err := auth2.New(ctx, cfg, tokenCache)
	if err != nil {
		log.Fatal(err)
	}

	login := &handlers2.LoginHandler{Auth: authSvc}
	callback := &handlers2.CallbackHandler{Auth: authSvc}
	apiKeys := auth2.ParseApiKeys(cfg)
	accessToken := handlers2.NewAccessTokenHandler(redisClient, encryptionService, apiKeys, tokenCache, authSvc.OAuth2Config)

	logoutHandler := handlers2.NewLogoutHandler(cfg, tokenCache)

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	mux.Handle("/oidc-callback", callback)
	mux.Handle("/access-token", accessToken)
	mux.Handle("/logout", logoutHandler)

	certFile := "cert.pem"
	keyFile := "key.pem"
	utils.GenerateSelfSignedCert(certFile, keyFile)

	log.Println("server started on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", certFile, keyFile, mux))
}
