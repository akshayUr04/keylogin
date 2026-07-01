// pkg/logger/logger.go
// Thin wrapper around go.uber.org/zap that provides a structured,
// levelled logger used throughout the application.  Callers import only
// this package – never zap directly – so the underlying library can be
// swapped without touching every call site.
package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps a *zap.Logger and exposes a clean interface.
type Logger struct {
	z *zap.Logger
}

// Field is a typed log field (alias for zap.Field).
type Field = zap.Field

// New creates a production-optimised logger for "production" / "staging"
// environments and a development-friendly (coloured, human-readable)
// logger otherwise.
func New(level, env string) (*Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zap.InfoLevel
	}

	var cfg zap.Config
	if env == "production" || env == "staging" {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)

	z, err := cfg.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, err
	}
	return &Logger{z: z}, nil
}

// Sync flushes any buffered log entries.
func (l *Logger) Sync() error { return l.z.Sync() }

// ── Levelled logging ────────────────────────────────────────────────────────

func (l *Logger) Debug(msg string, fields ...Field) { l.z.Debug(msg, fields...) }
func (l *Logger) Info(msg string, fields ...Field)  { l.z.Info(msg, fields...) }
func (l *Logger) Warn(msg string, fields ...Field)  { l.z.Warn(msg, fields...) }
func (l *Logger) Error(msg string, fields ...Field) { l.z.Error(msg, fields...) }
func (l *Logger) Fatal(msg string, fields ...Field) { l.z.Fatal(msg, fields...) }

// With returns a child logger with additional fixed fields attached to
// every log entry (useful for request-scoped loggers).
func (l *Logger) With(fields ...Field) *Logger {
	return &Logger{z: l.z.With(fields...)}
}

// ── Field constructors (thin shims around zap) ───────────────────────────────

// Field creates a generic string field.
func Field(key, val string) zap.Field { return zap.String(key, val) }

// Err creates an error field.
func Err(err error) zap.Field { return zap.Error(err) }

// Int creates an integer field.
func Int(key string, val int) zap.Field { return zap.Int(key, val) }

// Bool creates a boolean field.
func Bool(key string, val bool) zap.Field { return zap.Bool(key, val) }
