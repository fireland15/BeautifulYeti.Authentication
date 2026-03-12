package handlers

import (
	"beautifulyeti/authentication/internal/auth"
	"beautifulyeti/authentication/internal/config"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type LogoutHandler struct {
	cfg        config.Config
	tokenCache *auth.TokenCache
}

func NewLogoutHandler(cfg config.Config, tokenCache *auth.TokenCache) *LogoutHandler {
	return &LogoutHandler{
		cfg:        cfg,
		tokenCache: tokenCache,
	}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.SessionCookieName())
	var idToken string
	var sessionID string
	if err == nil {
		sessionID = cookie.Value
		// Clear the cookie
		http.SetCookie(w, &http.Cookie{
			Name:   h.cfg.SessionCookieName(),
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}

	tokens, err := h.tokenCache.Retrieve(r.Context(), sessionID)
	if err != nil {
		if !errors.Is(err, auth.ErrTokensNotFound) {
			w.WriteHeader(http.StatusInternalServerError)
			slog.Error("failed to retrieve tokens from cache", "err", err)
			return
		}
	} else {
		idToken = tokens.IDToken
	}

	endSessionURL := h.cfg.OIDCProviderLogoutURL()

	if idToken != "" {
		endSessionURL = fmt.Sprintf("%s&id_token_hint=%s", endSessionURL, idToken)
	}

	http.Redirect(w, r, endSessionURL, http.StatusFound)
}
