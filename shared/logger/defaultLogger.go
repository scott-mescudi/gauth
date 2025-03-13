package logger

import (
	"fmt"
	"io"
	"log"
)

// DefaultGauthLogger implements the GauthLogger interface and writes logs to a writer.
type DefaultGauthLogger struct {
	Writer io.Writer
}

// NewDefaultGauthLogger creates a new DefaultGauthLogger with a provided io.Writer.
func NewDefaultGauthLogger(writer io.Writer) *DefaultGauthLogger {
	return &DefaultGauthLogger{Writer: writer}
}

// Error writes an error message to the logger.
func (l *DefaultGauthLogger) Error(msg string) {
	logMessage := fmt.Sprintf("ERROR: %s\n", msg)
	l.write(logMessage)
}

// Warn writes a warning message to the logger.
func (l *DefaultGauthLogger) Warn(msg string) {
	logMessage := fmt.Sprintf("WARN: %s\n", msg)
	l.write(logMessage)
}

// Info writes an info message to the logger.
func (l *DefaultGauthLogger) Info(msg string) {
	logMessage := fmt.Sprintf("INFO: %s\n", msg)
	l.write(logMessage)
}

// Debug writes a debug message to the logger.
func (l *DefaultGauthLogger) Debug(msg string) {
	logMessage := fmt.Sprintf("DEBUG: %s\n", msg)
	l.write(logMessage)
}

// write is a helper function to write log messages to the writer.
func (l *DefaultGauthLogger) write(msg string) {
	if l.Writer != nil {
		_, err := l.Writer.Write([]byte(msg))
		if err != nil {
			log.Printf("Error writing log message: %v", err)
		}
	} else {
		log.Printf("No writer defined, log message: %s", msg)
	}
}
