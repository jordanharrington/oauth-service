package logger

import (
	"github.com/rs/zerolog"
	"os"
	"strings"
)

var log zerolog.Logger

func InitGlobalLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	defaultLogLevel := zerolog.InfoLevel
	zerolog.SetGlobalLevel(defaultLogLevel)
	log.Level(defaultLogLevel)

	logLevel := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevel != "" {
		if parsedLevel, err := zerolog.ParseLevel(logLevel); err == nil {
			zerolog.SetGlobalLevel(parsedLevel)
			log.Level(parsedLevel)
		} else {
			log.Warn().
				Err(err).
				Msgf("Invalid LOG_LEVEL '%s', falling back to default: %s", logLevel, defaultLogLevel.String())
		}
	}

	log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
		With().
		Timestamp().
		Logger()

	log.Info().
		Str("log_level", zerolog.GlobalLevel().String()).
		Msg("Logger initialized")
}

func Log() *zerolog.Logger {
	return &log
}
