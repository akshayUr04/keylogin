// internal/database/redis.go
// Redis client initialisation.  Used for session storage and token caching.
// The application uses go-redis/v9 which supports both standalone Redis
// and Redis Sentinel / Cluster.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedis parses the Redis URL and returns a connected client.
func NewRedis(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Redis URL: %w", err)
	}

	// Connection pool settings
	opts.PoolSize = 20
	opts.MinIdleConns = 5
	opts.ConnMaxIdleTime = 5 * time.Minute

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("pinging Redis: %w", err)
	}

	return client, nil
}
