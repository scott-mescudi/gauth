package logger

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

// DefaultGauthLogger implements the GauthLogger interface and writes logs to a writer.
type DefaultGauthLogger struct {
	Mu     *sync.Mutex
	Writer io.Writer
}

// NewDefaultGauthLogger creates a new DefaultGauthLogger with a provided io.Writer.
func NewDefaultGauthLogger(writer io.Writer) *DefaultGauthLogger {
	return &DefaultGauthLogger{
		Mu:     &sync.Mutex{},
		Writer: writer,
	}
}

// Error writes an error message to the logger.
func (l *DefaultGauthLogger) Error(msg string) {
	logMessage := l.formatLog("ERROR", msg)
	l.Mu.Lock()
	l.write(logMessage)
	l.Mu.Unlock()
}

// Warn writes a warning message to the logger.
func (l *DefaultGauthLogger) Warn(msg string) {
	logMessage := l.formatLog("WARN", msg)
	l.Mu.Lock()
	l.write(logMessage)
	l.Mu.Unlock()
}

// Info writes an info message to the logger.
func (l *DefaultGauthLogger) Info(msg string) {
	logMessage := l.formatLog("INFO", msg)
	l.Mu.Lock()
	l.write(logMessage)
	l.Mu.Unlock()
}

// Debug writes a debug message to the logger.
func (l *DefaultGauthLogger) Debug(msg string) {
	logMessage := l.formatLog("DEBUG", msg)
	l.Mu.Lock()
	l.write(logMessage)
	l.Mu.Unlock()
}

// formatLog generates the log message with a timestamp and level.
func (l *DefaultGauthLogger) formatLog(level, msg string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, msg)
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
