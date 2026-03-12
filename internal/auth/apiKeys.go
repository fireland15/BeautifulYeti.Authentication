package auth

import (
	"beautifulyeti/authentication/internal/config"
	"strings"
)

type ApiKeys map[string]string

func ParseApiKeys(cfg config.Config) ApiKeys {
	keyStr := cfg.SharedApiKeys()

	keys := map[string]string{}

	pairs := strings.Split(keyStr, ";")
	for _, p := range pairs {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) == 2 {
			name := parts[0]
			key := parts[1]
			keys[strings.TrimSpace(key)] = strings.TrimSpace(name)
		}
	}

	return keys
}

// Validate ensures the key is configured for the application and returns the name of the API it belongs to.
func (k ApiKeys) Validate(key string) (string, bool) {
	name, ok := k[key]
	if !ok {
		return "", false
	}
	return name, true
}
