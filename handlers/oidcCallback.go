package handlers

import (
	"beautifulyeti/authentication/auth"
	"encoding/json"
	"log/slog"
	"net/http"
)

type CallbackHandler struct {
	Auth *auth.Service
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	nonceCookie, err := r.Cookie("oidc_nonce")
	if err != nil {
		http.Error(w, "missing nonce", http.StatusBadRequest)
		return
	}

	oauth2Token, err := h.Auth.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusInternalServerError)
		return
	}

	idToken, err := h.Auth.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	if idToken.Nonce != nonceCookie.Value {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	deleteCookie(w, "oidc_state")
	deleteCookie(w, "oidc_nonce")

	tokenData := &auth.TokenData{
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		Expiry:       oauth2Token.Expiry,
		IDToken:      rawIDToken,
	}

	if err := h.Auth.StoreTokensAndIssueSession(ctx, w, tokenData); err != nil {
		slog.Error("failed to store tokens", "err", err)
		http.Error(w, "token store failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
