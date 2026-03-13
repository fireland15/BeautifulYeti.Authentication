package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/redis/go-redis/v9"
)

type HealthzHandler struct {
	redisClient *redis.Client
}

func NewHealthzHandler(redisClient *redis.Client) *HealthzHandler {
	return &HealthzHandler{redisClient: redisClient}
}

func (h *HealthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	redisOK := false

	if err := h.redisClient.Ping(r.Context()); err.Err() == nil {
		redisOK = true
	} else {
		status = "error"
		log.Println("Health check failed: Redis unreachable:", err)
	}

	type HealthResponse struct {
		Status  string `json:"status"`
		RedisOK bool   `json:"redis_ok"`
	}

	resp := HealthResponse{
		Status:  status,
		RedisOK: redisOK,
	}

	w.Header().Set("Content-Type", "application/json")
	if status != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}
