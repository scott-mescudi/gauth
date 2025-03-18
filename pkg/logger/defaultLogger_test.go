package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := NewDefaultGauthLogger(&buf)

	logger.Info("This is an info message")
	logger.Warn("This is a warning message")
	logger.Error("This is an error message")
	logger.Debug("This is a debug message")

	logOutput := buf.String()

	if !containsLog(logOutput, "INFO", "This is an info message") {
		t.Errorf("Expected info message, but got: %s", logOutput)
	}

	if !containsLog(logOutput, "WARN", "This is a warning message") {
		t.Errorf("Expected warn message, but got: %s", logOutput)
	}

	if !containsLog(logOutput, "ERROR", "This is an error message") {
		t.Errorf("Expected error message, but got: %s", logOutput)
	}

	if !containsLog(logOutput, "DEBUG", "This is a debug message") {
		t.Errorf("Expected debug message, but got: %s", logOutput)
	}
}

func containsLog(logOutput, level, msg string) bool {
	return strings.Contains(logOutput, level) && strings.Contains(logOutput, msg)
}

func TestLogWriting(t *testing.T) {
	var buf bytes.Buffer
	logger := NewDefaultGauthLogger(&buf)

	logger.Info("Log to writer")

	if buf.String() == "" {
		t.Error("Expected log message to be written to writer, but got empty output")
	}
}
