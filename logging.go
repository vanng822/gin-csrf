package csrf

import (
	"log"
	"os"
	"strings"
)

type LoggerInterface interface {
	Info(msg any, v ...any)
}

var (
	Logger LoggerInterface = &stdLogger{log.New(os.Stdout, "[gin-csrf]", log.LstdFlags)}
)

type stdLogger struct {
	logger *log.Logger
}

// Info logs a message at the Info level.
func (l *stdLogger) Info(msg any, args ...any) {
	// just a simple way to check if msg is a format string
	// if so, use Printf
	// else use Println
	if v, ok := msg.(string); ok && strings.Contains(v, "%") {
		l.logger.Printf(v, args...)
		return
	}

	args = append([]any{msg}, args...)
	l.logger.Println(args...)
}
