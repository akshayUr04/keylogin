// internal/repository/pkce_repository.go
// Redis-backed storage for PKCE flow state parameters.
// Each PKCE authorization request generates a unique state value linked to
// the code_verifier, realm, and client_id.  These are stored in Redis with
// a short TTL (5 minutes) and consumed exactly once during the callback.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

const (
	pkceKeyPrefix = "pkce:"
	pkceTTL       = 5 * time.Minute // PKCE state must be consumed within 5 minutes
)

// PKCEState holds the server-side state for an in-flight PKCE authorization.
type PKCEState struct {
	State        string `json:"state"`         // random state value (also the Redis key)
	CodeVerifier string `json:"code_verifier"` // PKCE code verifier (stored server-side, never sent to browser)
	Realm        string `json:"realm"`         // target Keycloak realm
	ClientID     string `json:"client_id"`     // public client ID used
	RedirectURI  string `json:"redirect_uri"`  // redirect URI for this flow
	Portal       string `json:"portal"`        // "admin" or "user" – determines post-login redirect
}

// PKCERepository stores and retrieves PKCE state from Redis.
type PKCERepository struct {
	redis *redis.Client
	log   *logger.Logger
}

// NewPKCERepository creates a PKCERepository backed by Redis.
func NewPKCERepository(rdb *redis.Client, log *logger.Logger) *PKCERepository {
	return &PKCERepository{redis: rdb, log: log}
}

func pkceKey(state string) string { return pkceKeyPrefix + state }

// Save stores PKCE state in Redis with an automatic 5-minute expiry.
func (r *PKCERepository) Save(ctx context.Context, state *PKCEState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshalling PKCE state: %w", err)
	}
	return r.redis.SetEx(ctx, pkceKey(state.State), string(b), pkceTTL).Err()
}

// Consume retrieves and deletes a PKCE state entry atomically.
// Returns nil, nil if the state does not exist (expired or already consumed).
func (r *PKCERepository) Consume(ctx context.Context, state string) (*PKCEState, error) {
	// Use GETDEL for atomic get-and-delete
	val, err := r.redis.GetDel(ctx, pkceKey(state)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("consuming PKCE state %q: %w", state, err)
	}

	var s PKCEState
	if err := json.Unmarshal([]byte(val), &s); err != nil {
		return nil, fmt.Errorf("unmarshalling PKCE state: %w", err)
	}
	return &s, nil
}
