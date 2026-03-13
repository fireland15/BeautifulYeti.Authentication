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
		slog.Info("method not allowed")
		return
	}

	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value == "" {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		slog.Info("state cookie missing")
		return
	}

	stateJson, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		http.Error(w, "decoding state cookie", http.StatusBadRequest)
		slog.Info("failed to decode state cookie")
		return
	}

	var stateValues map[string]string
	if err := json.Unmarshal(stateJson, &stateValues); err != nil {
		http.Error(w, "unmarshalling state", http.StatusBadRequest)
		slog.Info("failed to deserialize state")
		return
	}
	if state != stateValues["state"] {
		http.Error(w, "invalid state", http.StatusBadRequest)
		slog.Info("state is missing")
		return
	}

	nonceCookie, err := r.Cookie("oidc_nonce")
	if err != nil {
		http.Error(w, "missing nonce", http.StatusBadRequest)
		slog.Info("nonce cookie missing")
		return
	}

	oauth2Token, err := h.Auth.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		slog.Error("auth code exchange failed")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusInternalServerError)
		slog.Error("no id_token in auth code response")
		return
	}

	idToken, err := h.Auth.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		slog.Info("received invalid id_token from auth provider")
		return
	}

	if idToken.Nonce != nonceCookie.Value {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		slog.Info("invalid nonce")
		return
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		slog.Info("could not parse id_token claims")
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
		slog.Info("redirecting user", "location", redirectUrl)
		w.Header().Set("Location", redirectUrl)
		w.WriteHeader(http.StatusTemporaryRedirect)
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
