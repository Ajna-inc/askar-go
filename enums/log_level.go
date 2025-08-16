package enums

type LogLevel int32

const (
	LogLevelError LogLevel = 1
	LogLevelWarn  LogLevel = 2
	LogLevelInfo  LogLevel = 3
	LogLevelDebug LogLevel = 4
	LogLevelTrace LogLevel = 5
)