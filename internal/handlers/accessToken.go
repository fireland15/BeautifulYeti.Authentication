package handlers

import (
	auth2 "beautifulyeti/authentication/internal/auth"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// AccessTokenHandler handles requests to exchange a sessionID for an access token.
type AccessTokenHandler struct {
	redisClient *redis.Client
	encryption  *auth2.EncryptionService
}

func NewAccessTokenHandler(
	redisClient *redis.Client,
	encryption *auth2.EncryptionService) *AccessTokenHandler {
	return &AccessTokenHandler{
		redisClient: redisClient,
		encryption:  encryption,
	}
}

// ServeHTTP handles the /accessToken endpoint.
func (h *AccessTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// In a real-world scenario, you'd authenticate this request using client credentials
	// via your authorization provider. For simplicity, we'll assume it's trusted.

	var requestBody struct {
		SessionID string `json:"sessionId"`
	}

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

	// Retrieve the encrypted token data from Redis
	encryptedData, err := h.redisClient.Get(r.Context(), "session:"+requestBody.SessionID).Result()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "session not found")
		return
	}

	// Decrypt the token data
	decryptedData, err := h.encryption.DecryptToken(encryptedData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "failed to decrypt token data")
		return
	}

	// Unmarshal the JSON
	var tokenData auth2.TokenData
	if err := json.Unmarshal([]byte(decryptedData), &tokenData); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "failed to unmarshal token data")
		return
	}

	// Check if the access token is expired.
	if time.Now().After(tokenData.Expiry) {
		// In a real-world scenario, you'd refresh the tokens here
		// using the refresh token and store the new tokens.
		// For simplicity, we'll just return an error.
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "access token expired")
		return
	}

	// Return the access token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"accessToken": tokenData.AccessToken})
}
