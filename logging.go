package csrf

import (
	"log"
	"os"
)

type LoggerInterface interface {
	Info(msg ...any)
}

var (
	Logger LoggerInterface = &stdLogger{log.New(os.Stdout, "[gin-csrf]", log.LstdFlags)}
)

type stdLogger struct {
	logger *log.Logger
}

// Info logs a message at the Info level.
func (l *stdLogger) Info(msg ...any) {
	l.logger.Println(msg...)
}
