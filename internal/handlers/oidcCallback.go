package handlers

import (
	"beautifulyeti/authentication/internal/auth"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

type CallbackHandler struct {
	Auth *auth.Service
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value == "" {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}

	stateJson, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		http.Error(w, "decoding state cookie", http.StatusBadRequest)
		return
	}

	var stateValues map[string]string
	if err := json.Unmarshal(stateJson, &stateValues); err != nil {
		http.Error(w, "unmarshalling state", http.StatusBadRequest)
		return
	}
	if state != stateValues["state"] {
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

	redirectUrl, ok := stateValues["redirect_url"]
	if ok {
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Header().Set("Location", redirectUrl)
	} else {
		w.WriteHeader(http.StatusOK)
	}
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
