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
	authSvc, err := auth2.New(ctx, cfg, redisClient, encryptionService)
	if err != nil {
		log.Fatal(err)
	}

	login := &handlers2.LoginHandler{Auth: authSvc}
	callback := &handlers2.CallbackHandler{Auth: authSvc}
	accessToken := handlers2.NewAccessTokenHandler(redisClient, encryptionService)

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	mux.Handle("/oidc-callback", callback)
	mux.Handle("/access-token", accessToken)

	certFile := "cert.pem"
	keyFile := "key.pem"
	utils.GenerateSelfSignedCert(certFile, keyFile)

	log.Println("server started on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", certFile, keyFile, mux))
}
