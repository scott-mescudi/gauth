package logger

type GauthLogger interface {
	Error(msg string)
	Warn(msg string)
	Info(msg string)
	Debug(msg string)
}
