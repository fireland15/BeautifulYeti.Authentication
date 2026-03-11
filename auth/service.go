package auth

import (
	"beautifulyeti/authentication/config"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type Service struct {
	OAuth2Config  *oauth2.Config
	Verifier      *oidc.IDTokenVerifier
	redisClient   *redis.Client
	encryptionKey []byte
}

func New(ctx context.Context, cfg config.Config) (*Service, error) {
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

	redisClient := newRedisClient(cfg.RedisAddress(), cfg.RedisPassword())

	return &Service{
		OAuth2Config:  oauthCfg,
		Verifier:      verifier,
		redisClient:   redisClient,
		encryptionKey: cfg.EncryptionKey(),
	}, nil
}

func newRedisClient(addr, password string) *redis.Client {
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

func encryptToken(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decryptToken(ciphertextB64 string, key []byte) (string, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	return string(plaintext), err
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

	// 3. Marshal JSON
	tdJSON, err := json.Marshal(td)
	if err != nil {
		return err
	}

	// 4. Encrypt
	encrypted, err := encryptToken(string(tdJSON), s.encryptionKey)
	if err != nil {
		return err
	}

	// 5. Store in Redis
	err = s.redisClient.Set(ctx, "session:"+sessionID, encrypted, time.Until(tokens.Expiry)+time.Hour).Err()
	if err != nil {
		return err
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
