package handlers

import (
	"beautifulyeti/authentication/internal/auth"
	"beautifulyeti/authentication/internal/config"
	"errors"
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
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return
	}

	sessionID := cookie.Value
	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:   h.cfg.SessionCookieName(),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	if err := h.tokenCache.Delete(r.Context(), sessionID); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	endSessionURL := h.cfg.OIDCProviderLogoutURL()

	http.Redirect(w, r, endSessionURL, http.StatusFound)
}
