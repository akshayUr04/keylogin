// internal/repository/session_repository.go
// Redis-backed session repository.
// Sessions are stored as JSON blobs in Redis with an automatic TTL so
// they expire without any background cleanup job.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// SessionData holds the token set and metadata for an authenticated session.
type SessionData struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	RealmName    string    `json:"realm_name"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	Roles        []string  `json:"roles"`
	AppRole      string    `json:"app_role"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// SessionRepository stores and retrieves sessions from Redis.
type SessionRepository struct {
	redis *redis.Client
	log   *logger.Logger
}

// NewSessionRepository creates a SessionRepository backed by Redis.
func NewSessionRepository(rdb *redis.Client, log *logger.Logger) *SessionRepository {
	return &SessionRepository{redis: rdb, log: log}
}

const sessionKeyPrefix = "session:"

func sessionKey(id string) string { return sessionKeyPrefix + id }

// Save stores a session in Redis with the given TTL.
func (r *SessionRepository) Save(ctx context.Context, session *SessionData, ttl time.Duration) error {
	b, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshalling session: %w", err)
	}
	return r.redis.SetEx(ctx, sessionKey(session.SessionID), string(b), ttl).Err()
}

// Get retrieves a session by ID.  Returns nil, nil if not found.
func (r *SessionRepository) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	val, err := r.redis.Get(ctx, sessionKey(sessionID)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting session %q: %w", sessionID, err)
	}

	var s SessionData
	if err := json.Unmarshal([]byte(val), &s); err != nil {
		return nil, fmt.Errorf("unmarshalling session: %w", err)
	}
	return &s, nil
}

// Delete removes a session from Redis immediately.
func (r *SessionRepository) Delete(ctx context.Context, sessionID string) error {
	return r.redis.Del(ctx, sessionKey(sessionID)).Err()
}

// Touch updates the TTL (last-active timestamp) on an existing session.
func (r *SessionRepository) Touch(ctx context.Context, sessionID string, ttl time.Duration) error {
	return r.redis.Expire(ctx, sessionKey(sessionID), ttl).Err()
}

// UpdateAccessToken replaces the access token in an existing session.
func (r *SessionRepository) UpdateAccessToken(ctx context.Context, sessionID, accessToken, refreshToken string) error {
	s, err := r.Get(ctx, sessionID)
	if err != nil || s == nil {
		return err
	}
	s.AccessToken = accessToken
	s.RefreshToken = refreshToken
	s.LastActiveAt = time.Now()

	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session already expired")
	}
	return r.Save(ctx, s, ttl)
}
