package handlers

import (
	"beautifulyeti/authentication/internal/auth"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// AccessTokenHandler handles requests to exchange a sessionID for an access token.
type AccessTokenHandler struct {
	redisClient  *redis.Client
	encryption   *auth.EncryptionService
	apiKeys      *auth.ApiKeys
	tokenCache   *auth.TokenCache
	oauthConfig  *oauth2.Config
	refreshGroup singleflight.Group
}

func NewAccessTokenHandler(
	redisClient *redis.Client,
	encryption *auth.EncryptionService,
	apiKeys *auth.ApiKeys,
	tokenCache *auth.TokenCache,
	oauthConfig *oauth2.Config,
) *AccessTokenHandler {
	return &AccessTokenHandler{
		redisClient: redisClient,
		encryption:  encryption,
		apiKeys:     apiKeys,
		tokenCache:  tokenCache,
		oauthConfig: oauthConfig,
	}
}

// ServeHTTP handles the /accessToken endpoint.
func (h *AccessTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// authenticate the request with the api key
	apiKey := r.Header.Get("x-api-key")
	_, ok := h.apiKeys.Validate(apiKey)
	if apiKey == "" || !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "invalid api key")
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	var requestBody struct {
		SessionID string `json:"sessionId"`
	}
	
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "invalid request body")
		return
	}

	if requestBody.SessionID == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "sessionId is required")
		return
	}

	tokenData, err := h.tokenCache.Retrieve(r.Context(), requestBody.SessionID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "unable to load tokens for session")
		return
	}

	// determine if we should refresh
	if time.Until(tokenData.Expiry) <= 30*time.Second {
		sessionID := requestBody.SessionID
		v, err, _ := h.refreshGroup.Do(sessionID, func() (interface{}, error) {
			current, err := h.tokenCache.Retrieve(r.Context(), sessionID)
			if err != nil {
				return nil, err
			}

			return h.refreshTokens(r.Context(), sessionID, current)
		})

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		refreshed := v.(*auth.TokenData)
		tokenData = refreshed
	}

	resp := struct {
		AccessToken string `json:"accessToken"`
		Expires     int64  `json:"expires"`
		SessionID   string `json:"sessionId"`
	}{
		AccessToken: tokenData.AccessToken,
		Expires:     tokenData.Expiry.UTC().Unix(),
		SessionID:   requestBody.SessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
	}
}

var unlockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
else
	return 0
end
`)

func (h *AccessTokenHandler) refreshTokens(
	ctx context.Context,
	sessionID string,
	tokenData *auth.TokenData,
) (*auth.TokenData, error) {
	lockKey := fmt.Sprintf("session:%s:refresh-lock", sessionID)

	lockValue, err := generateRandomLockValue()
	if err != nil {
		return nil, err
	}

	result, err := h.redisClient.SetArgs(
		ctx,
		lockKey,
		lockValue,
		redis.SetArgs{
			Mode: string(redis.NX),
			TTL:  10 * time.Second,
		}).Result()
	if err != nil {
		return nil, err
	}

	locked := result == "OK"

	if !locked {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)

			updated, err := h.tokenCache.Retrieve(ctx, sessionID)
			if err == nil && updated != nil && updated.Expiry.After(time.Now().Add(10*time.Second)) {
				return updated, nil
			}
		}

		return nil, fmt.Errorf("timeout waiting for token refresh")
	}

	defer func() {
		_, _ = unlockScript.Run(ctx, h.redisClient, []string{lockKey}, lockValue).Result()
	}()

	oauthToken := &oauth2.Token{
		AccessToken:  tokenData.AccessToken,
		RefreshToken: tokenData.RefreshToken,
		Expiry:       tokenData.Expiry,
	}

	tokenSource := h.oauthConfig.TokenSource(ctx, oauthToken)

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	refreshToken := newToken.RefreshToken
	if refreshToken == "" {
		refreshToken = tokenData.RefreshToken
	}

	newTokenData := auth.TokenData{
		AccessToken:  newToken.AccessToken,
		RefreshToken: refreshToken,
		Expiry:       newToken.Expiry,
		IDToken:      tokenData.IDToken,
	}

	if err := h.tokenCache.Store(ctx, sessionID, &newTokenData); err != nil {
		return nil, err
	}

	return &newTokenData, nil
}

func generateRandomLockValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
