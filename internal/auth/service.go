package auth

import (
	"beautifulyeti/authentication/internal/config"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type Service struct {
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	tokens       *TokenCache
}

func New(ctx context.Context, cfg config.Config, tokens *TokenCache) (*Service, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCProviderURL())
	if err != nil {
		return nil, err
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.OIDCClientID(),
		ClientSecret: cfg.OIDCClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OIDCRedirectURL(),
		Scopes: []string{
			oidc.ScopeOpenID,
			"profile",
			"email",
		},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.OIDCClientID(),
	})

	return &Service{
		OAuth2Config: oauthCfg,
		Verifier:     verifier,
		tokens:       tokens,
	}, nil
}

func NewRedisClient(addr, password string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})
}

type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	IDToken      string    `json:"id_token"`
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) StoreTokensAndIssueSession(ctx context.Context, w http.ResponseWriter, tokens *TokenData) error {
	// 1. Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return err
	}

	// 2. Prepare TokenData
	td := TokenData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry,
		IDToken:      tokens.IDToken,
	}

	if err := s.tokens.Store(ctx, sessionID, &td); err != nil {
		return fmt.Errorf("error storing sessing tokens: %w", err)
	}

	// 6. Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}
