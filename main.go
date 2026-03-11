package main

import (
	"beautifulyeti/authentication/auth"
	"beautifulyeti/authentication/config"
	"beautifulyeti/authentication/handlers"
	"beautifulyeti/authentication/utils"
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

	authSvc, err := auth.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	login := &handlers.LoginHandler{Auth: authSvc}
	callback := &handlers.CallbackHandler{Auth: authSvc}

	mux := http.NewServeMux()
	mux.Handle("/login", login)
	mux.Handle("/oidc-callback", callback)

	certFile := "cert.pem"
	keyFile := "key.pem"
	utils.GenerateSelfSignedCert(certFile, keyFile)

	log.Println("server started on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", certFile, keyFile, mux))
}
