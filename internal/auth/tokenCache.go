package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenCache struct {
	redisClient *redis.Client
	encryption  *EncryptionService
}

func NewTokenCache(redisClient *redis.Client, encryption *EncryptionService) *TokenCache {
	return &TokenCache{
		redisClient: redisClient,
		encryption:  encryption,
	}
}

func (c *TokenCache) Store(ctx context.Context, sessionID string, tokenData *TokenData) error {
	tdJSON, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("marshaling tokens to json: %w", err)
	}

	encrypted, err := c.encryption.EncryptToken(tdJSON)
	if err != nil {
		return fmt.Errorf("encrypting tokens: %w", err)
	}

	key := createTokensKey(sessionID)
	err = c.redisClient.Set(ctx, key, encrypted, time.Until(tokenData.Expiry)+time.Hour).Err()
	if err != nil {
		return fmt.Errorf("saving tokens to redis client: %w", err)
	}

	return nil
}

func (c *TokenCache) Retrieve(ctx context.Context, sessionID string) (*TokenData, error) {
	redisKey := createTokensKey(sessionID)
	encryptedData, err := c.redisClient.Get(ctx, redisKey).Result()
	if err != nil {
		return nil, fmt.Errorf("getting session tokens from redis: %s", err)
	}

	decryptedData, err := c.encryption.DecryptToken(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decrypting token data: %w", err)
	}

	var tokenData TokenData
	if err := json.Unmarshal([]byte(decryptedData), &tokenData); err != nil {
		return nil, fmt.Errorf("unmarshaling token data: %w", err)
	}

	return &tokenData, nil
}

func createTokensKey(sessionID string) string {
	return fmt.Sprintf("session:%s:tokens", sessionID)
}
