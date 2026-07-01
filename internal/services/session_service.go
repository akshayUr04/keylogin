// internal/services/session_service.go
// Session management service.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// SessionService handles session state in Redis and Keycloak.
type SessionService struct {
	repo *repository.SessionRepository
	kc   *keycloak.Client
	log  *logger.Logger
}

// NewSessionService creates a SessionService.
func NewSessionService(repo *repository.SessionRepository, kc *keycloak.Client, log *logger.Logger) *SessionService {
	return &SessionService{repo: repo, kc: kc, log: log}
}

// GetSession retrieves a session by ID.
func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*repository.SessionData, error) {
	return s.repo.Get(ctx, sessionID)
}

// ListUserSessions returns all active Keycloak sessions for a user.
func (s *SessionService) ListUserSessions(ctx context.Context, realm, userID string) ([]models.Session, error) {
	kcSessions, err := s.kc.GetUserSessions(ctx, realm, userID)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	sessions := make([]models.Session, 0, len(kcSessions))
	for _, ks := range kcSessions {
		sessions = append(sessions, models.Session{
			ID:         ks.ID,
			UserID:     ks.UserID,
			Username:   ks.Username,
			IPAddress:  ks.IPAddress,
			Started:    time.Unix(ks.Start/1000, 0),
			LastAccess: time.Unix(ks.LastAccess/1000, 0),
			Clients:    ks.Clients,
		})
	}
	return sessions, nil
}

// TerminateSession terminates a Keycloak session.
func (s *SessionService) TerminateSession(ctx context.Context, realm, sessionID string) error {
	return s.kc.DeleteRealmSession(ctx, realm, sessionID)
}
