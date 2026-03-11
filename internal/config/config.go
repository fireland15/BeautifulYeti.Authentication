package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/dogmatiq/ferrite"
	"github.com/joho/godotenv"
)

var (
	encryptionKey = ferrite.String("ENCRYPTION_KEY", "Key for encryption").
			Required()

	oidcProviderUrl = ferrite.String("OIDC_PROVIDER_URL", "The OIDC provider URL").
			Required()
	oidcRedirectUrl = ferrite.String("OIDC_REDIRECT_URL", "The URL for OIDC callback").
			Required()
	oidcClientId = ferrite.String("OIDC_CLIENT_ID", "The application's client ID").
			Required()
	oidcClientSecret = ferrite.String("OIDC_CLIENT_SECRET", "The application's client secret").
				Required()

	redisAddress = ferrite.String("REDIS_ADDRESS", "The address of the Redis server").
			Required()
	redisPassword = ferrite.String("REDIS_PASSWORD", "The password of the Redis server").
			Required()
)

// Config interface defines the configuration methods.
type Config interface {
	EncryptionKey() []byte
	OIDCProviderURL() string
	OIDCRedirectURL() string
	OIDCClientID() string
	OIDCClientSecret() string
	RedisPassword() string
	RedisAddress() string
}

type config struct {
}

// EncryptionKey returns the encryption key as a byte slice.
func (c *config) EncryptionKey() []byte {
	v := encryptionKey.Value()
	hash := sha256.Sum256([]byte(v))
	return hash[:] // 32 bytes
}

// OIDCProviderURL returns the OIDC provider URL.
func (c *config) OIDCProviderURL() string {
	return oidcProviderUrl.Value()
}

// OIDCRedirectURL returns the OIDC redirect URL.
func (c *config) OIDCRedirectURL() string {
	return oidcRedirectUrl.Value()
}

// OIDCClientID returns the OIDC client ID.
func (c *config) OIDCClientID() string {
	return oidcClientId.Value()
}

// OIDCClientSecret returns the OIDC client secret.
func (c *config) OIDCClientSecret() string {
	return oidcClientSecret.Value()
}

// RedisPassword returns the Redis password.
func (c *config) RedisPassword() string {
	return redisPassword.Value()
}

// RedisAddress returns the Redis address.
func (c *config) RedisAddress() string {
	return redisAddress.Value()
}

// New returns a new config instance, or errors.
func New() (Config, error) {
	err := godotenv.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	ferrite.Init()
	return &config{}, nil
}
