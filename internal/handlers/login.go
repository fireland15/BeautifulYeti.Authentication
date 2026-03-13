package handlers

import (
	"beautifulyeti/authentication/internal/auth"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

type LoginHandler struct {
	Auth *auth.Service
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	state, err := generateState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	stateObj := map[string]interface{}{
		"state": state,
	}

	redirectURL := r.URL.Query().Get("redirect_url")
	if redirectURL != "" {
		stateObj["redirect_url"] = redirectURL
	}

	stateBytes, err := json.Marshal(stateObj)
	if err != nil {
		http.Error(w, "failed to encode state", http.StatusInternalServerError)
		return
	}

	encodedState := base64.RawURLEncoding.EncodeToString(stateBytes)
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    encodedState,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.Auth.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce))

	http.Redirect(w, r, url, http.StatusFound)
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
